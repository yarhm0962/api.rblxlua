import os
import random
import string
import io
import hashlib
from datetime import datetime, timedelta, timezone
from threading import Thread
import discord
from discord import app_commands, File, ui, ButtonStyle, SelectOption
from discord.ext import commands
import pymongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask import Flask, jsonify, request

TOKEN = os.getenv("TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
WEBSITE_DOMAIN = os.getenv("WEBSITE_DOMAIN", "api-rblxlua.onrender.com")

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
    return "-".join(full[i:i+4] for i in range(0, 16, 4))

def get_clean_domain():
    return WEBSITE_DOMAIN.replace("https://", "").replace("http://", "").rstrip("/")

def hash_hwid(raw_hwid):
    return hashlib.sha256(str(raw_hwid).strip().lower().encode()).hexdigest()

full_protection = '''local _v_t = type;local _v_p = pcall;local _v_xp = xpcall;local _v_r = rawget;local _v_rs = rawset;local _v_ts = tostring;local _v_req = rawequal;local _v_g = getfenv and getfenv() or _ENV or _G;local _v_err = error;local _v_sm = setmetatable;local function _v_logDetect()_v_p(_v_err, "Environment tampered");while true do end;end;local _real_dbg = _v_g["debug"];local _orig_di = _real_dbg and (_v_r(_real_dbg, "info") or _v_r(_real_dbg, "getinfo"));local _orig_tb = _real_dbg and _v_r(_real_dbg, "traceback");local _orig_gu = _real_dbg and _v_r(_real_dbg, "getupvalue");local _orig_su = _real_dbg and _v_r(_real_dbg, "setupvalue");local _iscc = _v_g["iscclosure"];local function _c_v(_fn)if _v_t(_fn) ~= "function" then return false end;if _iscc then local _s, _res = _v_p(_iscc, _fn);if _s and not _res then return false end end;if _orig_di then local _s, _res = _v_p(_orig_di, _fn);if _s and _v_t(_res) == "table" then if _res.what ~= "C" then return false end end end;return true;end;if not _c_v(_v_t) then _v_logDetect() end;if not _c_v(_v_p) then _v_logDetect() end;if not _c_v(_v_xp) then _v_logDetect() end;if not _c_v(_v_sm) then _v_logDetect() end;if not _c_v(_v_req) then _v_logDetect() end;if not _c_v(_v_r) then _v_logDetect() end;if not _c_v(_v_rs) then _v_logDetect() end;local _np = _v_g["newproxy"];local _secret_k = (_np and _c_v(_np)) and _np(false) or {};local _secret_v = (_np and _c_v(_np)) and _np(false) or {};local _proxy_active = false;local _self_ref;local function _v_tamperCheck()local _s1, _v3 = _v_p(function() return _v_g["Vector3"] end);if _s1 and _v3 then if not _c_v(_v3.new) then _v_logDetect() end;local _s2, _v3Res = _v_p(_v_ts, _v3.new(0,0,0));if _s2 and _v3Res ~= "0, 0, 0" then _v_logDetect() end end;local _s3, _en = _v_p(function() return _v_g["Enum"] end);if _s3 and _en then local _enT = _v_t(_en);if _enT ~= "userdata" and _enT ~= "table" then _v_logDetect() end end;if _v_g["print"] and not _c_v(_v_g["print"]) then _v_logDetect() end;if _v_g["warn"] and not _c_v(_v_g["warn"]) then _v_logDetect() end;if _v_g["error"] and not _c_v(_v_g["error"]) then _v_logDetect() end;if _proxy_active and _self_ref then local _s, _r = _v_p(function() return _self_ref[_secret_k] end);if not _s or not _v_req(_r, _secret_v) then _v_logDetect() end end;end;_v_tamperCheck();local _spoofMap = _v_sm({}, {__mode = "k"});local function _proxy_di(...)local _a1 = ...;if _v_t(_a1) == "function" and _v_r(_spoofMap, _a1) then _v_logDetect() end;if _orig_di then local _s, _res = _v_p(_orig_di, ...);if not _s then _v_logDetect() end;return _res end;return nil;end;local function _proxy_tb(...)if _orig_tb then local _s, _res = _v_p(_orig_tb, ...);return _res end;return "";end;local function _proxy_up(...)local _a1 = ...;if _v_t(_a1) == "function" and _v_r(_spoofMap, _a1) then _v_logDetect() end;if _orig_gu then local _s, _r1, _r2 = _v_p(_orig_gu, ...);if not _s then _v_logDetect() end;return _r1, _r2 end;return nil;end;local _s_cc, _newcc = _v_p(function() return _v_g["newcclosure"] end);_newcc = (_s_cc and _c_v(_newcc)) and _newcc or nil;local function _wrap(_fn)if _v_t(_fn) ~= "function" then return _fn end;local _proxy;if _newcc then _proxy = _newcc(function(...) _v_tamperCheck();return _fn(...) end);else _proxy = function(...) _v_tamperCheck();return _fn(...) end end;_v_rs(_spoofMap, _proxy, _fn);return _proxy;end;local _mt = {};_self_ref = _v_sm({}, _mt);local _ex_blk = {getrawmetatable = true, setrawmetatable = true, getreg = true, getgc = true, getgenv = true, getrenv = true, getupvalues = true, getupvalue = true, setupvalue = true};_mt.__index = function(_self, _k)if _v_req(_k, _secret_k) then return _secret_v end;_v_tamperCheck();if _k == "debug" then local _dbg_mt = {};local _dbg_proxy = _v_sm({["info"] = _proxy_di, ["getinfo"] = _proxy_di, ["traceback"] = _proxy_tb, ["getupvalue"] = _proxy_up, ["setupvalue"] = _proxy_up}, _dbg_mt);_dbg_mt.__index = function(_, _dk)local _r = _real_dbg and _v_r(_real_dbg, _dk);if _v_t(_r) == "function" then return _wrap(_r) end;return _r end;_dbg_mt.__newindex = function() _v_logDetect() end;_dbg_mt.__metatable = false;return _dbg_proxy end;if _v_r(_ex_blk, _k) then return function() _v_logDetect();return nil end end;if _k == "iscclosure" and _iscc then return function(_fn)if _v_r(_spoofMap, _fn) then _v_logDetect() end;return _c_v(_fn) end end;if _k == "tostring" and _v_ts then return function(_fn)if _v_r(_spoofMap, _fn) then _v_logDetect() end;return _v_ts(_fn) end end;if _k == "getfenv" then return function(_l)local _lvl = _v_t(_l) == "number" and _l or 1;if _lvl > 1 then _v_logDetect() end;return _self_ref end end;local _s, _r = _v_p(function() return _v_g[_k] end);if _s and _r ~= nil then if _v_t(_r) == "function" then return _wrap(_r) end;return _r end;return nil;end;_mt.__newindex = function(_self, _k, _val)_v_tamperCheck();_v_p(function() _v_g[_k] = _val end) end;local function _pnlty() _v_logDetect();return function() end end;_mt.__pairs = _pnlty;_mt.__ipairs = _pnlty;_mt.__len = function() _v_logDetect();return 0 end;_mt.__tostring = function() _v_logDetect();return '' end;_mt.__call = _pnlty;_mt.__concat = _pnlty;_mt.__unm = _pnlty;_mt.__add = _pnlty;_mt.__sub = _pnlty;_mt.__mul = _pnlty;_mt.__div = _pnlty;_mt.__mod = _pnlty;_mt.__pow = _pnlty;_mt.__metatable = false;_proxy_active = true;local _s_set, _setfenv = _v_p(function() return _v_g["setfenv"] end);if _s_set and _v_t(_setfenv) == "function" then if not _c_v(_setfenv) then _v_logDetect() end;_v_p(function() local _s_ge, _rEnv = _v_p(getfenv, 2);if _s_ge and not _v_req(_rEnv, _self_ref) then _setfenv(2, _self_ref) end end) end;local _envProxy = _self_ref;local getfenv = function() return _envProxy end;local _ENV = _envProxy;local _G = _envProxy;local AntiTamper = {};local function random_str()local s = "";for i = 1, math.random(7, 12) do s = s .. string.char(math.random(97, 122)) end;return s;end;local function to_hex(str)local out = "";for i = 1, #str do out = out .. "\\" .. str:byte(i) end;return '"' .. out .. '"';end;function AntiTamper.apply(src)local lines = {};local counter = "c_" .. random_str();local add = "add_" .. random_str();table.insert(lines, "local " .. counter .. " = 0");table.insert(lines, "local function " .. add .. "() " .. counter .. " = " .. counter .. " + 1 end");local checks = {[[local b = buffer.create(16)buffer.writeu32(b, 0, 0xDEADBEEF)if buffer.readu32(b, 0) ~= 3735928559 or buffer.len(b) ~= 16 then ]] .. add .. [[() end]],[[local b2 = buffer.create(4)buffer.writeu8(b2, 0, 255)if buffer.readu8(b2, 0) ~= 255 then ]] .. add .. [[() end]],[[if game:GetService(]] .. to_hex("RunService") .. [[):IsStudio() then ]] .. add .. [[() end]],[[if #game:GetService(]] .. to_hex("HttpService") .. [[):JSONEncode({test = 123}) < 5 then ]] .. add .. [[() end]],[[if workspace.Gravity == 0 or workspace:FindFirstChild(]] .. to_hex("NonExistentChild") .. [[) then ]] .. add .. [[() end]]};for i = #checks, 2, -1 do local j = math.random(i);checks[i], checks[j] = checks[j], checks[i] end;for _, code in ipairs(checks) do table.insert(lines, "pcall(function() " .. code .. " end)") end;local msg = to_hex("Security Violation");table.insert(lines, [[if ]] .. counter .. [[ > 0 then local p = game.Players.LocalPlayer;if p then p:Kick(]] .. msg .. [[) end;while true do task.wait();pcall(function() error(]] .. msg .. [[, 0) end) end end]]);return "task.spawn(function()\n" .. table.concat(lines, "\n") .. "\nend)\n" .. src;end'''

class KeySelectView(ui.View):
    def __init__(self, user_keys, action_type: str):
        super().__init__(timeout=120)
        self.user_keys = user_keys
        self.action_type = action_type
        options = []
        for idx, k in enumerate(user_keys):
            s = scripts_col.find_one({"script_id": k["script_id"]})
            label = s["name"][:45] if s else f"Script {idx+1}"
            options.append(SelectOption(label=label, value=k["key"], description=f"Key: {k['key'][:8]}..."))
        self.select_menu = ui.Select(placeholder="Select which key to use", options=options, custom_id="key:select")
        self.select_menu.callback = self.on_key_selected
        self.add_item(self.select_menu)

    async def on_key_selected(self, interaction: discord.Interaction):
        selected_key = self.select_menu.values[0]
        key_data = keys_col.find_one({"key": selected_key, "user_id": str(interaction.user.id), "active": True})
        script = scripts_col.find_one({"script_id": key_data["script_id"]})
        if self.action_type == "stats":
            uses = key_data["uses_left"] if key_data["uses_left"] is not None else "Unlimited"
            exp = "Never"
            if key_data.get("expires_at"): exp = key_data["expires_at"].strftime("%Y-%m-%d %H:%M UTC")
            emb = discord.Embed(title="📊 Your Key Stats", color=0x95a5a6)
            emb.add_field(name="Script", value=f"`{script['name']}`", inline=False)
            emb.add_field(name="Key", value=f"`{key_data['key']}`", inline=False)
            emb.add_field(name="Uses Remaining", value=f"`{uses}`", inline=False)
            emb.add_field(name="Expires", value=f"`{exp}`", inline=False)
            return await interaction.response.edit_message(embed=emb, view=None)
        elif self.action_type == "script":
            domain = get_clean_domain()
            file_url = f"https://{domain}/v3/loaders/file/{key_data['script_id']}.lua"
            file_content = f'getgenv().SCRIPT_KEY = "{key_data["key"]}"\nloadstring(game:HttpGet("{file_url}"))()'
            file = File(io.BytesIO(file_content.encode("utf-8")), filename=script["filename"])
            emb = discord.Embed(title="📜 Your Script", color=0x2ecc71)
            emb.add_field(name="Loader", value=f"`getgenv().SCRIPT_KEY = \"{key_data['key']}\"`\n`loadstring(game:HttpGet(\"{file_url}\"))()`", inline=False)
            return await interaction.response.edit_message(embed=emb, view=None, attachments=[file])

class PanelView(ui.View):
    def __init__(self, script_id: str):
        super().__init__(timeout=None)
        self.script_id = script_id

    @ui.button(label="Redeem Key", emoji="🔑", style=ButtonStyle.green, custom_id="panel:redeem")
    async def redeem_btn(self, interaction: discord.Interaction, button: ui.Button):
        class SafeRedeemModal(ui.Modal, title="Redeem Your Key"):
            key_input = ui.TextInput(label="Enter Your Key", placeholder="NllN-llNl-NNlN-lNNl", min_length=19, max_length=19, required=True)
            async def on_submit(this, int: discord.Interaction):
                key_val = this.key_input.value.strip().lower()
                key_data = keys_col.find_one({"key": key_val, "active": True})
                if not key_data: return await int.response.send_message("❌ Invalid or inactive key", ephemeral=True)
                if key_data["script_id"] != interaction.extras.get("target_script_id"): return await int.response.send_message("❌ This key is for a different script", ephemeral=True)
                if key_data["expires_at"] and datetime.now(timezone.utc) > key_data["expires_at"]: return await int.response.send_message("❌ This key has expired", ephemeral=True)
                if key_data["uses_left"] is not None and key_data["uses_left"] <= 0: return await int.response.send_message("❌ This key has no uses left", ephemeral=True)
                keys_col.update_one({"key": key_val},{"$set":{"user_id": str(int.user.id), "redeemed_at": datetime.now(timezone.utc)}})
                if key_data["uses_left"] is not None: keys_col.update_one({"key": key_val},{"$inc":{"uses_left": -1}})
                script_data = scripts_col.find_one({"script_id": key_data["script_id"]})
                if script_data.get("auto_apply") and script_data.get("role_id"):
                    role = int.guild.get_role(int(script_data["role_id"]))
                    if role: await int.user.add_roles(role)
                await int.response.send_message(f"✅ Key redeemed successfully for **{script_data['name']}**", ephemeral=True)
        modal = SafeRedeemModal()
        modal.extras = {"target_script_id": self.script_id}
        await interaction.response.send_modal(modal)

    @ui.button(label="Get Script", emoji="📜", style=ButtonStyle.blurple, custom_id="panel:getscript")
    async def getscript_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_keys = list(keys_col.find({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True}))
        if not user_keys: return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        if len(user_keys) == 1:
            domain = get_clean_domain()
            k = user_keys[0]
            script = scripts_col.find_one({"script_id": self.script_id})
            file_url = f"https://{domain}/v3/loaders/file/{self.script_id}.lua"
            file_content = f'getgenv().SCRIPT_KEY = "{k["key"]}"\nloadstring(game:HttpGet("{file_url}"))()'
            file = File(io.BytesIO(file_content.encode("utf-8")), filename=script["filename"])
            emb = discord.Embed(title="📜 Your Script", color=0x2ecc71)
            emb.add_field(name="Loader", value=f"`getgenv().SCRIPT_KEY = \"{k['key']}\"`\n`loadstring(game:HttpGet(\"{file_url}\"))()`", inline=False)
            return await interaction.response.send_message(embed=emb, file=file, ephemeral=True)
        view = KeySelectView(user_keys, "script")
        await interaction.response.send_message("🔽 Select the key you want to use:", view=view, ephemeral=True)

    @ui.button(label="Get Role", emoji="👤", style=ButtonStyle.blurple, custom_id="panel:getrole")
    async def getrole_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_keys = list(keys_col.find({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True}))
        if not user_keys: return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        script = scripts_col.find_one({"script_id": self.script_id})
        if not script or not script.get("role_id"): return await interaction.response.send_message("❌ No role set for this script", ephemeral=True)
        role = interaction.guild.get_role(int(script["role_id"]))
        if not role: return await interaction.response.send_message("❌ Role not found", ephemeral=True)
        if role in interaction.user.roles: return await interaction.response.send_message("✅ You already have this role", ephemeral=True)
        await interaction.user.add_roles(role)
        await interaction.response.send_message(f"✅ Role added: {role.mention}", ephemeral=True)

    @ui.button(label="Reset HWID", emoji="⚙️", style=ButtonStyle.grey, custom_id="panel:resethwid")
    async def resethwid_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_keys = list(keys_col.find({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True}))
        if not user_keys: return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        hwid_col.delete_many({"user_id": str(interaction.user.id), "script_id": self.script_id})
        await interaction.response.send_message("✅ HWID cleared. Will re-register on next run", ephemeral=True)

    @ui.button(label="Get Stats", emoji="📊", style=ButtonStyle.grey, custom_id="panel:getstats")
    async def getstats_btn(self, interaction: discord.Interaction, button: ui.Button):
        user_keys = list(keys_col.find({"user_id": str(interaction.user.id), "script_id": self.script_id, "active": True}))
        if not user_keys: return await interaction.response.send_message("❌ Redeem a valid key first", ephemeral=True)
        if len(user_keys) == 1:
            k = user_keys[0]
            script = scripts_col.find_one({"script_id": self.script_id})
            uses = k["uses_left"] if k["uses_left"] is not None else "Unlimited"
            exp = "Never"
            if k.get("expires_at"): exp = k["expires_at"].strftime("%Y-%m-%d %H:%M UTC")
            emb = discord.Embed(title="📊 Your Key Stats", color=0x95a5a6)
            emb.add_field(name="Script", value=f"`{script['name']}`", inline=False)
            emb.add_field(name="Key", value=f"`{k['key']}`", inline=False)
            emb.add_field(name="Uses Remaining", value=f"`{uses}`", inline=False)
            emb.add_field(name="Expires", value=f"`{exp}`", inline=False)
            return await interaction.response.send_message(embed=emb, ephemeral=True)
        view = KeySelectView(user_keys, "stats")
        await interaction.response.send_message("🔽 Select which key to view stats:", view=view, ephemeral=True)

@bot.event
async def on_ready():
    bot.add_view(PanelView("placeholder"))
    await tree.sync()
    print(f"✅ Bot Ready | Logged in as {bot.user}")

@tree.command(name="create-script", description="Create new script and panel")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(role_id="Role ID to give", auto_apply="Auto add role", provider="Provider name (optional)", file="Lua or text file", embed_title="Panel title", embed_description="Panel description")
async def create_script_cmd(interaction: discord.Interaction, role_id: str, auto_apply: bool, file: discord.Attachment, embed_title: str, embed_description: str = None, provider: str = None):
    await interaction.response.defer(ephemeral=False)
    if not file.filename.endswith((".lua", ".txt")): return await interaction.followup.send("❌ Only .lua or .txt files allowed", ephemeral=True)
    file_content = await file.read()
    script_id = os.urandom(16).hex()
    if not embed_description: embed_description = f"This control panel is for the project: **{embed_title}**\nRedeem a valid key to get started."
    script_data = {"script_id": script_id, "name": embed_title, "role_id": role_id, "auto_apply": auto_apply, "provider": provider, "filename": file.filename, "content": file_content.decode("utf-8", errors="replace"), "embed_title": embed_title, "embed_description": embed_description, "created_at": datetime.now(timezone.utc)}
    scripts_col.insert_one(script_data)
    panel_emb = discord.Embed(title=embed_title, description=embed_description, color=0x3498db)
    panel_emb.set_footer(text=f"Script ID: {script_id}" + (f" | Provider: {provider}" if provider else ""))
    view = PanelView(script_id)
    panel_msg = await interaction.followup.send(embed=panel_emb, view=view)
    scripts_col.update_one({"script_id": script_id}, {"$set": {"panel_message_id": str(panel_msg.id), "panel_channel_id": str(interaction.channel.id)}})
    confirm_emb = discord.Embed(title="✅ Created Successfully", color=0x2ecc71)
    confirm_emb.add_field(name="Script ID", value=f"`{script_id}`", inline=False)
    confirm_emb.add_field(name="Domain", value=f"`{get_clean_domain()}`", inline=False)
    await interaction.followup.send(embed=confirm_emb, ephemeral=True)

@tree.command(name="generate-key", description="Generate new access key")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(script_id="Target Script ID", max_uses="Max uses (0 = unlimited)", expires_days="Expires in days (0 = never)")
async def generate_key_cmd(interaction: discord.Interaction, script_id: str, max_uses: int = 0, expires_days: int = 0):
    await interaction.response.defer(ephemeral=True)
    exists = scripts_col.find_one({"script_id": script_id})
    if not exists: return await interaction.followup.send("❌ Script ID not found", ephemeral=True)
    key_value = generate_formatted_key()
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days) if expires_days > 0 else None
    key_data = {"key": key_value, "script_id": script_id, "uses_left": max_uses if max_uses > 0 else None, "max_uses": max_uses, "expires_at": expires_at, "active": True, "created_at": datetime.now(timezone.utc)}
    keys_col.insert_one(key_data)
    emb = discord.Embed(title="✅ Key Generated", color=0x2ecc71)
    emb.add_field(name="Key", value=f"`{key_value}`", inline=False)
    emb.add_field(name="Script", value=f"`{script_id}`", inline=False)
    emb.add_field(name="Uses", value=f"`{'Unlimited' if max_uses == 0 else max_uses}`", inline=False)
    emb.add_field(name="Expires", value=f"`{'Never' if expires_days == 0 else f'{expires_days} days'}`", inline=False)
    await interaction.followup.send(embed=emb, ephemeral=True)

@app.route('/v3/loaders/file/<script_id>.lua')
def serve_script(script_id):
    script = scripts_col.find_one({"script_id": script_id})
    if not script: return "Not Found", 404

    key_check_code = '''local _K = getgenv and getgenv().SCRIPT_KEY or _G.SCRIPT_KEY or ""
if not _K or #_K < 19 then game:GetService("Players").LocalPlayer:Kick("Missing or invalid SCRIPT_KEY\\nSet with: getgenv().SCRIPT_KEY = \"YOUR_KEY\"") return end
local _D = "''' + get_clean_domain() + '''"
local _U = "https://".._D.."/v3/verify?key=".._K.."&script="..tostring(''' + script_id + ''')
local _S, _R = pcall(function() return game:GetService("HttpService"):JSONDecode(game:HttpGet(_U)) end)
if not _S or not _R or not _R.get("valid", false) then game:GetService("Players").LocalPlayer:Kick("Key verification failed") return end
local _HWID = nil
pcall(function() _HWID = game:GetService("GuiService"):GetPlatformUserId() end)
if not _HWID then pcall(function() _HWID = game:GetService("UserInputService"):GetDeviceId() end) end
if not _HWID then pcall(function() _HWID = tostring(game.Players.LocalPlayer.UserId) end) end
local _HASH = ("%064x")%tonumber((hashlib and hashlib.sha256 or string.len)(tostring(_HWID)))
local _CH = loadstring(game:HttpGet(_U.."&hwid=".._HASH))()
if _CH and _CH ~= true then game:GetService("Players").LocalPlayer:Kick("HWID Mismatched - Contact Admin to reset") return end
'''

    final_code = full_protection + "\n" + key_check_code + "\nAntiTamper.apply([==[" + script["content"] + "]==])"
    return final_code, 200, {"Content-Type": "text/plain; charset=utf-8"}

@app.route('/v3/verify', methods=["GET"])
def verify_key():
    key = request.args.get("key")
    script_id = request.args.get("script")
    raw_hwid = request.args.get("hwid")
    if not key or not script_id: return jsonify({"valid": False}), 400
    key_data = keys_col.find_one({"key": key, "script_id": script_id, "active": True})
    if not key_data: return jsonify({"valid": False}), 200
    if key_data.get("expires_at") and datetime.now(timezone.utc) > key_data["expires_at"]: return jsonify({"valid": False}), 200
    if key_data.get("uses_left") is not None and key_data["uses_left"] <= 0: return jsonify({"valid": False}), 200

    if raw_hwid:
        hashed = hash_hwid(raw_hwid)
        existing = hwid_col.find_one({"key": key, "script_id": script_id})
        if not existing:
            hwid_col.insert_one({"key": key, "script_id": script_id, "hwid_hash": hashed, "created_at": datetime.now(timezone.utc)})
        else:
            if existing["hwid_hash"] != hashed: return jsonify({"valid": True, "hwid_ok": False}), 200
    return jsonify({"valid": True, "hwid_ok": True}), 200

@app.errorhandler(404)
def page_not_found(e): return jsonify(error="Not Found"), 404

def run_flask(): app.run(host="0.0.0.0", port=10000)

if __name__ == "__main__":
    Thread(target=run_flask, daemon=True).start()
    bot.run(TOKEN)
