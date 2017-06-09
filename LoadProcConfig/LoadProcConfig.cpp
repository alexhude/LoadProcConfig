//
// LoadProcConfig.cpp
// Load Processor Config
//
// Created by Alexander Hude on 31/03/16.
// Copyright (c) 2017 Fried Apple Team. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>

// The netnode helper.
// Using this node we will save current configuration information in the IDA database.
static netnode helper;

char device[MAXSTR] = "";
char cfgfile[QMAXFILE];

//--------------------------------------------------------------------------

#include <name.hpp>
#include <offset.hpp>
#include <diskio.hpp>

static size_t numports = 0;
static ioport_t *ports = NULL;

#define NO_GET_CFG_PATH

inline void get_cfg_filename(char *buf, size_t bufsize, bool user = false)
{
	buf[0] = '\0';

	if (user == true)
	{
		int back_cnt = 0;
		size_t base_offset = 0;

		char* filename = askfile2_c(false, nullptr, "*.cfg", "Load Processor Configuration");

		if (nullptr == filename)
			return;

		// choose_ioport_device() only supports path relative to 'cfg' folder in IDA
		// therefore we need to generate it from our destination path

		// get 'cfg' path
		char cfg_path[QMAXFILE] = {0};
		qstrncpy(cfg_path, idadir(CFG_SUBDIR), QMAXFILE);

		// find common base and generate path to it from the source
		while (qstrstr(filename, cfg_path) == nullptr)
		{
			char* slash_pos = qstrrchr(cfg_path, '/');
			if (slash_pos == nullptr)
				break;

			qstrncat(buf, "../", bufsize);
			slash_pos[0] = 0;
			back_cnt++;
		}
		base_offset = strlen(cfg_path);

		// create relative path to destination
		qstrncat(buf, filename + base_offset + 1, bufsize); // exclude left '/' from path
	}
	else
	{
		qstrncpy(buf, cfgfile, bufsize);
	}
}

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#include "../module/iocommon.cpp"

//--------------------------------------------------------------------------
void run(int)
{
	get_cfg_filename(cfgfile, QMAXFILE, true);

	if (strlen(cfgfile) == 0)
		return;

	msg("ProcConf: loading config \"%s\"...\n", cfgfile);

	if ( choose_ioport_device(cfgfile, device, sizeof(device), NULL) )
	{
		msg("ProcConf: ... done\n");
		if (qstrcmp(device, "NONE") != 0)
		{
			msg("ProcConf: device chosen \"%s\"\n", device);

			int resp_info = IORESP_ALL;
			display_infotype_dialog(IORESP_ALL, &resp_info, cfgfile);

			set_device_name(device, resp_info);
			noUsed(0, BADADDR); // reanalyze program
		}
	}
	else
	{
		msg("ProcConf: ... failed\n");
	}
}

//--------------------------------------------------------------------------

const ioport_t *find_sym(ea_t address)
{
	return find_ioport(ports, numports, address);
}

int idaapi hook(void* user_data, int notification_code, va_list va)
{
	switch (notification_code) {
		case processor_t::custom_outop:
		{
			op_t* op = va_arg(va, op_t *);
			if (op->type == o_imm)
			{
				const ioport_t * port = find_sym(op->value);
				if ( port != NULL )
				{
					out_line(port->name, COLOR_IMPNAME);
					return 2;
				}
			}
			break;
		}
		default:
			break;
	}

	return 0;
}

//--------------------------------------------------------------------------
int init(void)
{
  hook_to_notification_point(HT_IDP, hook, NULL);
  return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void term(void)
{
  unhook_from_notification_point(HT_IDP, hook, NULL);
}

//--------------------------------------------------------------------------
char help[] = "Load Processor Config";
char comment[] = "This module allows to load processor configuration files";
char wanted_name[] = "Load Processor Config";
char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
