#include <sourcemod>
#include <calladmin>
#include <discord>

#define PLUGIN_VERSION "1.5"

#define REPORT_MSG "{\"username\":\"{BOTNAME}\", \"content\":\"{MENTION}\",\"attachments\": [{\"color\": \"{COLOR}\",\"title\": \"{HOSTNAME} (steam://connect/{SERVER_IP}:{SERVER_PORT}){REFER_ID}\",\"fields\": [{\"title\": \"Reason\",\"value\": \"{REASON}\",\"short\": true},{\"title\": \"Reporter\",\"value\": \"{REPORTER_NAME} ([{REPORTER_ID}](https://steamcommunity.com/profiles/{REPORTER_ID64}))\",\"short\": true},{\"title\": \"Target\",\"value\": \"{TARGET_NAME} ([{TARGET_ID}](https://steamcommunity.com/profiles/{TARGET_ID64}))\",\"short\": true}],\"footer\": \"DiscordWatch\",\"ts\": \"{TIMESTAMP}\"}]}"
#define CLAIM_MSG "{\"username\":\"{BOTNAME}\", \"content\":\"{MSG}\",\"attachments\": [{\"color\": \"{COLOR}\",\"title\": \"{HOSTNAME} (steam://connect/{SERVER_IP}:{SERVER_PORT})\",\"fields\": [{\"title\": \"Admin\",\"value\": \"{ADMIN}\",\"short\": false},{\"title\": \"Steam ID\",\"value\": \"[{ADMIN_ID}](https://steamcommunity.com/profiles/{ADMIN_ID64})\",\"short\": false}],\"footer\": \"DiscordWatch\",\"ts\": \"{TIMESTAMP}\"}]}"

char sSymbols[25][1] = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};

char g_sHostPort[6];
char g_sServerName[256];
char g_sHostIP[16];

const char[][] keywords = { "hack", "exploit", "grief", "ahk", "wall", "cheat", "aimbot" };


ConVar g_cBotName = null;
ConVar g_cClaimMsg = null;
ConVar g_cColor = null;
ConVar g_cColor2 = null;
ConVar g_cColor3 = null;
ConVar g_cMention = null;
ConVar g_cMention2 = null;
ConVar g_cRemove = null;
ConVar g_cRemove2 = null;
ConVar g_cWebhook = null;

public Plugin myinfo = 
{
	name = "DiscordWatch: Calladmin",
	author = ".#Zipcore, sneaK",
	description = "",
	version = PLUGIN_VERSION,
	url = "www.zipcore.net"
}

public void OnPluginStart()
{
	CreateConVar("discord_calladmin_version", PLUGIN_VERSION, "Discord CallAdmin version", FCVAR_DONTRECORD|FCVAR_SPONLY|FCVAR_REPLICATED|FCVAR_NOTIFY);
	
	g_cBotName = CreateConVar("discord_calladmin_botname", "Call Admin", "Report botname, leave this blank to use the webhook default name.");
	g_cClaimMsg = CreateConVar("discord_calladmin_claimmsg", "Report has been claimed by an admin.", "Message to send when admin uses the claim command.");
	g_cColor = CreateConVar("discord_calladmin_color", "#ff2222", "Discord/Slack attachment color used for reports.");
	g_cColor2 = CreateConVar("discord_calladmin_color2", "#22ff22", "Discord/Slack attachment color used for admin claims.");
	g_cColor3 = CreateConVar("discord_calladmin_color3", "#ff9911", "Discord/Slack attachment color used for admin reports.");
	g_cMention = CreateConVar("discord_calladmin_mention", "<@&264106385761894400>", "This allows you to mention reports, leave blank to disable.");
	g_cMention2 = CreateConVar("discord_calladmin_mention2", "<@&546037192783298571>", "This allows you to mention an alternate role, leave blank to disable.");
	g_cRemove = CreateConVar("discord_calladmin_remove", " | By PulseServers.com", "Remove this part from servername before sending the report.");
	g_cRemove2 = CreateConVar("discord_calladmin_remove2", "sneaK's ", "Remove this part from servername before sending the report.");
	g_cWebhook = CreateConVar("discord_calladmin_webhook", "calladmin", "Config key from configs/discord.cfg.");
	
	AutoExecConfig(true, "discord_calladmin");
	
	RegAdminCmd("sm_claim", Cmd_Claim, ADMFLAG_GENERIC);
}

public void OnAllPluginsLoaded()
{
	if (!LibraryExists("calladmin"))
	{
		SetFailState("CallAdmin not found");
		return;
	}
	
	UpdateIPPort();
	CallAdmin_GetHostName(g_sServerName, sizeof(g_sServerName));
}

void UpdateIPPort()
{
	GetConVarString(FindConVar("hostport"), g_sHostPort, sizeof(g_sHostPort));
	
	if(FindConVar("net_public_adr") != null)
		GetConVarString(FindConVar("net_public_adr"), g_sHostIP, sizeof(g_sHostIP));
	
	if(strlen(g_sHostIP) == 0 && FindConVar("ip") != null)
		GetConVarString(FindConVar("ip"), g_sHostIP, sizeof(g_sHostIP));
	
	if(strlen(g_sHostIP) == 0 && FindConVar("hostip") != null)
	{
		int ip = GetConVarInt(FindConVar("hostip"));
		FormatEx(g_sHostIP, sizeof(g_sHostIP), "%d.%d.%d.%d", (ip >> 24) & 0x000000FF, (ip >> 16) & 0x000000FF, (ip >> 8) & 0x000000FF, ip & 0x000000FF);
	}
}

public void CallAdmin_OnServerDataChanged(ConVar convar, ServerData type, const char[] oldVal, const char[] newVal)
{
	if (type == ServerData_HostName)
		CallAdmin_GetHostName(g_sServerName, sizeof(g_sServerName));
}

public Action Cmd_Claim(int client, int args)
{
    char sName[(MAX_NAME_LENGTH + 1) * 2];
    char clientAuth[21];
    char clientAuth64[32];

    GetClientInfo(client, sName, sizeof(sName), clientAuth, sizeof(clientAuth), clientAuth64, sizeof(clientAuth64));
    RemoveStringsFromServerName();
    char sClaimMsg[512];
    GetClaimMessage(sClaimMsg, sizeof(sClaimMsg));

    char sBot[512];
    g_cBotName.GetString(sBot, sizeof(sBot));

    char sColor[8];
    g_cColor2.GetString(sColor, sizeof(sColor));

    char szTimestamp[64];
    GetTimestamp(szTimestamp, sizeof(szTimestamp));

    char sMSG[512] = CLAIM_MSG;
    BuildClaimMessage(sMSG, sizeof(sMSG), sBot, sColor, sName, clientAuth, clientAuth64, sClaimMsg, szTimestamp);

    SendMessage(sMSG);
    ReplyToCommand(client, "Claim sent successfully!");

    return Plugin_Handled;
}

void GetClientInfo(int client, char[] sName, int nameSize, char[] clientAuth, int authSize, char[] clientAuth64, int auth64Size)
{
    if (client == 0)
    {
        strcopy(sName, nameSize, "CONSOLE");
    }
    else
    {
        GetClientAuthId(client, AuthId_Steam2, clientAuth, authSize);
        GetClientAuthId(client, AuthId_SteamID64, clientAuth64, auth64Size);
        GetClientName(client, sName, nameSize);
        Discord_EscapeString(sName, nameSize);
    }
}

void RemoveStringsFromServerName()
{
    char sRemove[64];
    g_cRemove.GetString(sRemove, sizeof(sRemove));
    ReplaceString(g_sServerName, sizeof(g_sServerName), sRemove, "");

    g_cRemove2.GetString(sRemove, sizeof(sRemove));
    ReplaceString(g_sServerName, sizeof(g_sServerName), sRemove, "");

    Discord_EscapeString(g_sServerName, sizeof(g_sServerName));
}

void GetClaimMessage(char[] sClaimMsg, int size)
{
    g_cClaimMsg.GetString(sClaimMsg, size);
    Discord_EscapeString(sClaimMsg, size);
}

void BuildClaimMessage(char[] sMSG, int size, const char[] sBot, const char[] sColor, const char[] sName, const char[] clientAuth, const char[] clientAuth64, const char[] sClaimMsg, const char[] szTimestamp)
{
    ReplaceString(sMSG, size, "{BOTNAME}", sBot);
    ReplaceString(sMSG, size, "{COLOR}", sColor);
    ReplaceString(sMSG, size, "{ADMIN}", sName);
    ReplaceString(sMSG, size, "{ADMIN_ID}", clientAuth);
    ReplaceString(sMSG, size, "{ADMIN_ID64}", clientAuth64);
    ReplaceString(sMSG, size, "{MSG}", sClaimMsg);
    ReplaceString(sMSG, size, "{HOSTNAME}", g_sServerName);
    ReplaceString(sMSG, size, "{SERVER_IP}", g_sHostIP);
    ReplaceString(sMSG, size, "{SERVER_PORT}", g_sHostPort);
    ReplaceString(sMSG, size, "{TIMESTAMP}", szTimestamp);
}


public void CallAdmin_OnReportPost(int client, int target, const char[] reason)
{
    char sColor[8];
    GetColor(client, sColor, sizeof(sColor));

    char sReason[(REASON_MAX_LENGTH + 1) * 2];
    PrepareString(reason, sReason, sizeof(sReason));

    char clientAuth[21], clientAuth64[32], clientName[(MAX_NAME_LENGTH + 1) * 2];
    PrepareClientInfo(client, clientAuth, sizeof(clientAuth), clientAuth64, sizeof(clientAuth64), clientName, sizeof(clientName));

    char targetAuth[21], targetAuth64[32], targetName[(MAX_NAME_LENGTH + 1) * 2];
    PrepareClientInfo(target, targetAuth, sizeof(targetAuth), targetAuth64, sizeof(targetAuth64), targetName, sizeof(targetName));

    CleanServerName();

    char sMention[512], sMention2[512], sBot[512];
    GetStringValues(sMention, sizeof(sMention), sMention2, sizeof(sMention2), sBot, sizeof(sBot));

    char szTimestamp[64];
    GetTimestamp(szTimestamp, sizeof(szTimestamp));

    char sMSG[4096] = REPORT_MSG;
    BuildMessage(sMSG, sizeof(sMSG), sBot, sColor, sReason, clientName, clientAuth, clientAuth64, targetName, targetAuth, targetAuth64, szTimestamp);
    SendMessage(sMSG);
}

void GetColor(int client, char[] sColor, int size)
{
    if(!CheckCommandAccess(client, "sm_mute", ADMFLAG_CHAT, true))
        g_cColor.GetString(sColor, size);
    else
        g_cColor3.GetString(sColor, size);
}

void PrepareString(const char[] input, char[] output, int size)
{
    strcopy(output, size, input);
    Discord_EscapeString(output, size);
}

void PrepareClientInfo(int client, char[] clientAuth, int authSize, char[] clientAuth64, int auth64Size, char[] clientName, int nameSize)
{
    if (client == REPORTER_CONSOLE)
    {
        strcopy(clientName, nameSize, "Server");
        strcopy(clientAuth, authSize, "CONSOLE");
    }
    else
    {
        GetClientAuthId(client, AuthId_Steam2, clientAuth, authSize);
        GetClientAuthId(client, AuthId_SteamID64, clientAuth64, auth64Size);
        GetClientName(client, clientName, nameSize);
        Discord_EscapeString(clientName, nameSize);
    }
}

void CleanServerName()
{
    char sRemove[64];
    for (int i = 1; i <= 2; i++)
    {
        if (i == 1)
            g_cRemove.GetString(sRemove, sizeof(sRemove));
        else
            g_cRemove2.GetString(sRemove, sizeof(sRemove));

        if (!StrEqual(sRemove, ""))
            ReplaceString(g_sServerName, sizeof(g_sServerName), sRemove, "");
    }

    Discord_EscapeString(g_sServerName, sizeof(g_sServerName));
}

void GetStringValues(char[] sMention, int mentionSize, char[] sMention2, int mention2Size, char[] sBot, int botSize)
{
    g_cMention.GetString(sMention, mentionSize);
    g_cMention2.GetString(sMention2, mention2Size);
    g_cBotName.GetString(sBot, botSize);
}

void GetTimestamp(char[] szTimestamp, int size)
{
    int gettime = GetTime();
    IntToString(gettime, szTimestamp, size);
}

void BuildMessage(char[] sMSG, int size, const char[] sBot, const char[] sColor, const char[] sReason, const char[] clientName, const char[] clientAuth, const char[] clientAuth64, const char[] targetName, const char[] targetAuth, const char[] targetAuth64, const char[] szTimestamp)
{
    ReplaceString(sMSG, size, "{BOTNAME}", sBot);
    ReplaceString(sMSG, size, "{COLOR}", sColor);
    ReplaceString(sMSG, size, "{REASON}", sReason);
    ReplaceString(sMSG, size, "{REPORTER_NAME}", clientName);
    ReplaceString(sMSG, size, "{REPORTER_ID}", clientAuth);
    ReplaceString(sMSG, size, "{REPORTER_ID64}", clientAuth64);
    ReplaceString(sMSG, size, "{TARGET_NAME}", targetName);
    ReplaceString(sMSG, size, "{TARGET_ID}", targetAuth);
    ReplaceString(sMSG, size, "{TARGET_ID64}", targetAuth64);
    ReplaceString(sMSG, size, "{HOSTNAME}", g_sServerName);
    ReplaceString(sMSG, size, "{SERVER_IP}", g_sHostIP);
    ReplaceString(sMSG, size, "{SERVER_PORT}", g_sHostPort);

    // If the report reason contains specific keywords, use sMention; otherwise, use sMention2
if (ContainsAnyKeyword(sReason, keywords, sizeof(keywords) / sizeof(keywords[0]), false))
        ReplaceString(sMSG, size, "{MENTION}", sMention);
    else
        ReplaceString(sMSG, size, "{MENTION}", sMention2);

    char sRefer[16];
    Format(sRefer, sizeof(sRefer), " # %s%s-%d%d", sSymbols[GetRandomInt(0, 25 - 1)], sSymbols[GetRandomInt(0, 25 - 1)], GetRandomInt(0, 9), GetRandomInt(0, 9));
    ReplaceString(sMSG, size, "{REFER_ID}", sRefer);
    ReplaceString(sMSG, size, "{TIMESTAMP}", szTimestamp);
}

bool ContainsAnyKeyword(const char[] str, const char[][] keywords, int numKeywords, bool caseSensitive)
{
    for (int i = 0; i < numKeywords; i++)
    {
        if (StrContains(str, keywords[i], caseSensitive) != -1)
        {
            return true;
        }
    }
    return false;
}



SendMessage(char[] sMessage)
{
	char sWebhook[32];
	g_cWebhook.GetString(sWebhook, sizeof(sWebhook));
	Discord_SendMessage(sWebhook, sMessage);
}