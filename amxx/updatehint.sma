/*  AMXModX Script
*
*   Title:    Update Client Hint
*   Author:   Lev
*   Changelog:
*   23.03.2010
*   - Added HLTV recognition
*/

#pragma semicolon 1
#pragma ctrlchar '\'

#include <amxmodx>
#include <amxmisc>
#include <amxconst>
#include <fun>
#include <regex>

#define AUTH_NONE 		0	// "N/A" - slot is free
#define AUTH_DPROTO		1	// dproto
#define AUTH_STEAM		2	// Native Steam
#define AUTH_STEAMEMU		3	// SteamEmu
#define AUTH_REVEMU		4	// RevEmu
#define AUTH_OLDREVEMU		5	// Old RevEmu
#define AUTH_HLTV		6	// HLTV

new const PLUGIN[]  = "UpdateHint";
new const VERSION[] = "1.1";
new const AUTHOR[]  = "Lev";

const BASE_TASK_ID_HINT = 3677;	// random number
const BASE_TASK_ID_KICK = 6724;	// random number
const MIN_SHOW_INTERVAL = 20;	// minimum constrain for hint show interval
const MAX_URL_LENGTH = 70;		// max length of the URL

new bool:playerPutOrAuth[33];	// Player was put in server or auth.

new pcvar_uh_url;
new pcvar_uh_interval;
new pcvar_uh_kickinterval;
new pcvar_dp_r_protocol;
new pcvar_dp_r_id_provider;

public plugin_init()
{
	register_plugin(PLUGIN, VERSION, AUTHOR);
	register_cvar("updatehint", VERSION, FCVAR_SERVER | FCVAR_SPONLY | FCVAR_UNLOGGED);

	register_dictionary("updatehint.txt");

	pcvar_uh_url = register_cvar("uh_url", "http://some.addr/somefile");	// URL where player can goto to download new client.
	pcvar_uh_interval = register_cvar("uh_interval", "60.0");		// Interval between hint shows.
	pcvar_uh_kickinterval = register_cvar("uh_kickinterval", "0");	// Interval bwfoew kick client.
	pcvar_dp_r_protocol = get_cvar_pointer ("dp_r_protocol");		// Dproto interface.
	pcvar_dp_r_id_provider = get_cvar_pointer ("dp_r_id_provider");	// Dproto interface.
}

public client_connect(id)
{
	playerPutOrAuth[id] = false;
}

public client_authorized(id)
{
	if (playerPutOrAuth[id])
	{
		return check_client_type(id);
	}
	playerPutOrAuth[id] = true;
	return PLUGIN_CONTINUE;
}

public client_putinserver(id)
{
	if (playerPutOrAuth[id])
	{
		return check_client_type(id);
	}
	playerPutOrAuth[id] = true;
	return PLUGIN_CONTINUE;
}

check_client_type(id)
{
	if (!pcvar_dp_r_protocol || !pcvar_dp_r_id_provider)
		return PLUGIN_CONTINUE;

	server_cmd("dp_clientinfo %d", id);
	server_exec();

	new proto = get_pcvar_num(pcvar_dp_r_protocol);
	new authprov = get_pcvar_num(pcvar_dp_r_id_provider);

	switch(authprov)
	{
		case AUTH_DPROTO:
			console_print(0, "Protocol: %d, authprovaider: %s", proto, "DPROTO");
		case AUTH_STEAM:
			console_print(0, "Protocol: %d, authprovaider: %s", proto, "STEAM");
		case AUTH_REVEMU:
			console_print(0, "Protocol: %d, authprovaider: %s", proto, "REVEMU");
		case AUTH_STEAMEMU:
			console_print(0, "Protocol: %d, authprovaider: %s", proto, "STEAMEMU");
		case AUTH_OLDREVEMU:
			console_print(0, "Protocol: %d, authprovaider: %s", proto, "OLDREVEMU");
		case AUTH_HLTV:
			console_print(0, "Protocol: %d, authprovaider: %s", proto, "HLTV");
	}

	if (proto < 48 || (authprov != AUTH_STEAM && authprov != AUTH_REVEMU && authprov != AUTH_HLTV))
	{
		set_task(get_uh_interval(), "show_update_hint", BASE_TASK_ID_HINT + id, _, _, "b");
		new kick_interval = get_pcvar_num(pcvar_uh_kickinterval);
		if (kick_interval > 0)
			set_task(float(kick_interval), "kick_client", BASE_TASK_ID_KICK + id);
	}

	return PLUGIN_CONTINUE;
}

public client_disconnect(id)
{
	remove_task(BASE_TASK_ID_HINT + id);
	remove_task(BASE_TASK_ID_KICK + id);
}

Float:get_uh_interval()
{
	new interval = get_pcvar_num(pcvar_uh_interval);
	// Check to be no less then minimum value
	return float((interval < MIN_SHOW_INTERVAL ) ? MIN_SHOW_INTERVAL : interval);
}

public show_update_hint(id)
{
	id -= BASE_TASK_ID_HINT;
	if (0 > id || id > 31)
		return;
	new url[MAX_URL_LENGTH];
	get_pcvar_string(pcvar_uh_url, url, charsmax(url));
	set_hudmessage(255, 100, 100, -1.0, 0.35, 0, 3.0, 5.0, 0.1, 0.1, 4);
	show_hudmessage(id, "%L", id, "HUDHINT");
	client_print(id, print_chat, "%L", id, "CHATHINT", url);
}

public kick_client(id)
{
	id -= BASE_TASK_ID_KICK;
	if (0 > id || id > 31)
		return;
	new url[MAX_URL_LENGTH];
	get_pcvar_string(pcvar_uh_url, url, charsmax(url));
	client_print(id, print_chat, "%L", id, "CHATHINT", url);
	new userid = get_user_userid(id);
	server_cmd("kick #%d \"%L\"", userid, id, "HUDHINT");
}