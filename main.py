import os
import random
import string
import io
from datetime import datetime, timedelta, timezone
from threading import Thread
import discord
from discord import app_commands, File, ui, ButtonStyle
from discord.ext import commands
import pymongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask import Flask

TOKEN = os.getenv("TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
WEBSITE_DOMAIN = os.getenv("WEBSITE_DOMAIN")

app = Flask(__name__)

mongo_client = MongoClient(MONGODB_URI, server_api=ServerApi('1'))
db = mongo_client["rblxlua_panel"]
scripts_col = db["scripts"]
keys_col = db["keys"]
hwid_col = db["hwids"]

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=None, intents=intents, help_command=None)
tree = bot.tree

def generate_formatted_key():
    nums = string.digits
    lets = string.ascii_lowercase
    pattern = ["N","l","l","N","l","l","N","l","N","N","l","N","l","N","N","l"]
    res = []
    for p in pattern:
        if p == "N":
            res.append(random.choice(nums))
        else:
            res.append(random.choice(lets))
    full = "".join(res)
    return "-".join(full[i:i+4] for i in range(0,16,4))

class RedeemModal(ui.Modal, title="Redeem Your Key"):
    key_input = ui.TextInput(label="Enter Your Key", placeholder="NllN-llNl-NNlN-lNNl", min_length=19, max_length=19, required=True)

    async def on_submit(self, interaction: discord.Interaction):
        key_val = self.key_input.value.strip().lower()
        key_data = keys_col.find_one({"key": key_val, "active": True})
        if not key_data:
            return await interaction.response.send_message("❌ Invalid or inactive key", ephemeral=True)
        if key_data["expires_at"] and datetime.now(timezone.utc) > key_data["expires_at"]:
            return await interaction.response.send_message("❌ This key has expired", ephemeral=True)
        if key_data["uses_left"] is not None and key_data["uses_left"] <= 0:
            return await interaction.response.send_message("❌ This key has no uses left", ephemeral=True)
        script_data = scripts_col.find_one({"script_id": key_data["script_id"]})
        if not script_data:
            return await interaction.response.send_message("❌ Linked script not found", ephemeral=True)
        existing = keys_col.find_one({"user_id": str(interaction.user.id), "script_id": key_data["script_id"]})
        if existing and existing["key"] != key_val:
            return await interaction.response.send_message("❌ You already have a key registered for this script", ephemeral=True)
        keys_col.update_one({"key": key_val}, {"$set": {"user_id": str(interaction.user.id), "redeemed_at": datetime.now(timezone.utc)}})
        if key_data["uses_left"] is not None:
            keys_col.update_one({"key": key_val}, {"$inc": {"uses_left": -1}})
        if script_data["auto_apply"] and script_data["role_id"]:
            role = interaction.guild.get_role(int(script_data["role_id"]))
            if role:
                await interaction.user.add_roles(role)
        await interaction.response.send_message(f"✅ Key redeemed successfully for **{script_data['name']}**", ephemeral=True)

class PanelView(ui.View):
    def __init__(self, script_id: str):
        super().__init__(timeout=None)
        self.script_id = script_id

    @ui.button(label="Redeem Key", emoji="🔑", style=ButtonStyle.green, custom_id="panel:redeem")
    async def redeem_btn(self, interaction: discord.Interaction, button: ui.Button):
        await interaction.response.send_modal(RedeemModal())

    @ui.button(label="Get Script", emoji="📜", style=ButtonStyle.blurple, custom_id="panel:getscript")
    async def getscript_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_key = keys_col.find_one({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True})
        if not user_key:
            return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        script = scripts_col.find_one({"script_id": self.script_id})
        if not script:
            return await interaction.response.send_message("❌ Script not found", ephemeral=True)
        file_content = f'getgenv().SCRIPT_KEY = "{user_key["key"]}"\n\nloadstring(game:HttpGet("https://{WEBSITE_DOMAIN}/v3/loaders/file/net.{self.script_id}.lua"))()'
        file = File(io.BytesIO(file_content.encode("utf-8")), filename=script["filename"])
        emb = discord.Embed(title="📜 Your Script", color=0x2ecc71)
        emb.add_field(name="Loader", value=f"`getgenv().SCRIPT_KEY = \"{user_key['key']}\"`\n`loadstring(game:HttpGet(\"https://{WEBSITE_DOMAIN}/v3/loaders/file/net.{self.script_id}.lua\"))()`", inline=False)
        await interaction.response.send_message(embed=emb, file=file, ephemeral=True)

    @ui.button(label="Get Role", emoji="👤", style=ButtonStyle.blurple, custom_id="panel:getrole")
    async def getrole_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_key = keys_col.find_one({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True})
        if not user_key:
            return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        script = scripts_col.find_one({"script_id": self.script_id})
        if not script or not script["role_id"]:
            return await interaction.response.send_message("❌ No role set for this script", ephemeral=True)
        role = interaction.guild.get_role(int(script["role_id"]))
        if not role:
            return await interaction.response.send_message("❌ Role not found", ephemeral=True)
        if role in interaction.user.roles:
            return await interaction.response.send_message("✅ You already have the role", ephemeral=True)
        await interaction.user.add_roles(role)
        await interaction.response.send_message(f"✅ Given role: {role.mention}", ephemeral=True)

    @ui.button(label="Reset HWID", emoji="⚙️", style=ButtonStyle.grey, custom_id="panel:resethwid")
    async def resethwid_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_key = keys_col.find_one({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True})
        if not user_key:
            return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        hwid_col.delete_one({"user_id": str(interaction.user.id), "script_id": self.script_id})
        await interaction.response.send_message("✅ HWID cleared. You will be asked to set it again next run", ephemeral=True)

    @ui.button(label="Get Stats", emoji="📊", style=ButtonStyle.grey, custom_id="panel:getstats")
    async def getstats_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_key = keys_col.find_one({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True})
        if not user_key:
            return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        script = scripts_col.find_one({"script_id": self.script_id})
        uses = user_key["uses_left"] if user_key["uses_left"] is not None else "Unlimited"
        exp = "Never"
        if user_key["expires_at"]:
            exp = user_key["expires_at"].strftime("%Y-%m-%d %H:%M UTC")
        emb = discord.Embed(title="📊 Your Stats", color=0x95a5a6)
        emb.add_field(name="Script", value=f"`{script['name']}`", inline=False)
        emb.add_field(name="Uses Remaining", value=f"`{uses}`", inline=False)
        emb.add_field(name="Expires", value=f"`{exp}`", inline=False)
        await interaction.response.send_message(embed=emb, ephemeral=True)

@bot.event
async def on_ready():
    bot.add_view(PanelView("placeholder"))
    await tree.sync()
    print(f"Ready: {bot.user}")

@tree.command(name="create-script", description="Create new script and control panel")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(
    role_id="Role ID to give",
    auto_apply="Automatically give role",
    provider="Provider name",
    file="Lua or text file",
    embed_title="Panel title",
    embed_description="Panel description"
)
async def create_script_cmd(
    interaction: discord.Interaction,
    role_id: str,
    auto_apply: bool,
    provider: str,
    file: discord.Attachment,
    embed_title: str,
    embed_description: str = None
):
    await interaction.response.defer()
    if not file.filename.endswith((".lua", ".txt")):
        return await interaction.followup.send("❌ Only .lua or .txt allowed", ephemeral=True)
    file_content = await file.read()
    script_id = os.urandom(16).hex()
    if not embed_description:
        embed_description = f"This control panel is for the project: **{embed_title}**\nIf you're a buyer, click on the buttons below to redeem your key, get the script or get your role"
    script_data = {
        "script_id": script_id,
        "name": embed_title,
        "role_id": role_id,
        "auto_apply": auto_apply,
        "provider": provider,
        "filename": file.filename,
        "content": file_content.decode("utf-8", errors="replace"),
        "embed_title": embed_title,
        "embed_description": embed_description,
        "created_at": datetime.now(timezone.utc)
    }
    scripts_col.insert_one(script_data)
    panel_emb = discord.Embed(title=embed_title, description=embed_description, color=0x3498db)
    panel_emb.set_footer(text=f"Script ID: {script_id} | Provider: {provider}")
    view = PanelView(script_id)
    panel_msg = await interaction.followup.send(embed=panel_emb, view=view)
    scripts_col.update_one({"script_id": script_id}, {"$set": {"panel_message_id": str(panel_msg.id), "panel_channel_id": str(interaction.channel.id)}})
    confirm_emb = discord.Embed(title="✅ Script & Panel Created", color=0x2ecc71)
    confirm_emb.add_field(name="Script ID", value=f"`{script_id}`", inline=False)
    confirm_emb.add_field(name="Panel Created", value="✅ Sent here", inline=False)
    await interaction.followup.send(embed=confirm_emb, ephemeral=True)

@tree.command(name="generate-key", description="Generate new access key")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(
    script_id="Target Script ID",
    max_uses="Max uses (0 = unlimited)",
    expires_days="Expires in days (0 = never)"
)
async def generate_key_cmd(
    interaction: discord.Interaction,
    script_id: str,
    max_uses: int = 0,
    expires_days: int = 0
):
    await interaction.response.defer()
    exists = scripts_col.find_one({"script_id": script_id})
    if not exists:
        return await interaction.followup.send("❌ Script ID not found", ephemeral=True)
    key_value = generate_formatted_key()
    expires_at = None
    if expires_days > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
    key_data = {
        "key": key_value,
        "script_id": script_id,
        "uses_left": max_uses if max_uses > 0 else None,
        "max_uses": max_uses,
        "expires_at": expires_at,
        "active": True,
        "created_at": datetime.now(timezone.utc)
    }
    keys_col.insert_one(key_data)
    embed = discord.Embed(title="✅ Key Generated", color=0x3498db)
    embed.add_field(name="Key", value=f"`{key_value}`", inline=False)
    embed.add_field(name="For Script", value=f"`{script_id}`", inline=False)
    embed.add_field(name="Max Uses", value=f"{max_uses}" if max_uses>0 else "Unlimited", inline=False)
    embed.add_field(name="Expires", value=f"{expires_days} days" if expires_days>0 else "Never", inline=False)
    await interaction.followup.send(embed=embed)

@app.route('/v3/loaders/file/net.<script_id>.lua')
def serve_script(script_id):
    script = scripts_col.find_one({"script_id": script_id})
    if not script: return "Not Found", 404
    return script["content"], 200, {"Content-Type":"text/plain; charset=utf-8"}

def run_flask():
    app.run(host="0.0.0.0", port=10000, use_reloader=False)

if __name__ == "__main__":
    Thread(target=run_flask, daemon=True).start()
    bot.run(TOKEN)
