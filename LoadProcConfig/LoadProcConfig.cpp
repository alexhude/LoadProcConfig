//
// LoadProcConfig.cpp
// Load Processor Config
//
// Created by Alexander Hude on 31/03/16.
// Copyright (c) 2017 Alexander Hude. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>

#if (IDA_SDK_VERSION < 700) && defined(__X64__)
	#error Incompatible SDK version. Please use SDK 7.0 or higher
#elif (IDA_SDK_VERSION >= 700) && !defined(__X64__)
	#error Incompatible SDK version. Please use SDK 6.95 or lower
#endif

#if IDA_SDK_VERSION >= 700
	#define idaapi_hook_cb_ret_t							ssize_t

	#define IDAAPI_AskFile(save, defdir, filter, format)	ask_file(save, filter, format)
	#define IDAAPI_PlanRange								plan_range
	#define idaapi_out_operand								ev_out_operand
#else
	#define idaapi_hook_cb_ret_t							int

	#define IDAAPI_AskFile(save, defdir, filter, format)	askfile2_c(save, defdir, filter, format)
	#define IDAAPI_PlanRange								noUsed
	#define idaapi_out_operand								custom_outop
#endif

// The netnode helper.
// Using this node we will save current configuration information in the IDA database.
static netnode helper;

#if IDA_SDK_VERSION >= 700
qstring g_device;
#else
char g_device[MAXSTR] = "";
#endif
char g_cfgfile[QMAXFILE];

#ifdef _WIN32
	char dir_sep = '\\';
	char dir_up[] = "..\\";
#else
	char dir_sep = '/';
	char dir_up[] = "../";
#endif

//--------------------------------------------------------------------------

#include <name.hpp>
#include <offset.hpp>
#include <diskio.hpp>

#if IDA_SDK_VERSION >= 700
	static ioports_t ports;
#else
	static size_t numports = 0;
	static ioport_t *ports = NULL;
#endif

#define NO_GET_CFG_PATH

inline void get_cfg_filename(char *buf, size_t bufsize, bool user = false)
{
	buf[0] = '\0';

	if (user == true)
	{
		int back_cnt = 0;
		size_t base_offset = 0;

		char* filename = IDAAPI_AskFile(false, nullptr, "*.cfg", "Load Processor Configuration");

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
			char* slash_pos = qstrrchr(cfg_path, dir_sep);
			if (slash_pos == nullptr)
				break;

			qstrncat(buf, dir_up, bufsize);
			slash_pos[0] = 0;
			back_cnt++;
		}
		base_offset = strlen(cfg_path);

		// create relative path to destination
		qstrncat(buf, filename + base_offset + 1, bufsize); // exclude left '/' from path
	}
	else
	{
		qstrncpy(buf, g_cfgfile, bufsize);
	}
}

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#if IDA_SDK_VERSION >= 760
    #include "../module/iohandler.hpp"
    struct lpc_iohandler_t : public iohandler_t {
        lpc_iohandler_t(netnode &nn) : iohandler_t(nn) {}
        void get_cfg_filename(char *buf, size_t bufsize) override {
            qstrncpy(buf, g_cfgfile, bufsize);
        }
    };
#else
    #include "../module/iocommon.cpp"
#endif

//--------------------------------------------------------------------------
#if IDA_SDK_VERSION >= 700
bool run(size_t)
{
#if IDA_SDK_VERSION >= 760
    netnode iohelper;
    lpc_iohandler_t ioh = lpc_iohandler_t(iohelper);
#endif
    
	get_cfg_filename(g_cfgfile, QMAXFILE, true);
	
	if (strlen(g_cfgfile) == 0)
		return false;
	
	msg("ProcConf: loading config \"%s\"...\n", g_cfgfile);
	
	if ( choose_ioport_device(&g_device, g_cfgfile, NULL) )
	{
		msg("ProcConf: ... done\n");
		if (qstrcmp(g_device.c_str(), "NONE") != 0)
		{
			msg("ProcConf: device chosen \"%s\"\n", g_device.c_str());
			
			int resp_info = IORESP_ALL;
        #if IDA_SDK_VERSION >= 760
			ioh.display_infotype_dialog(IORESP_ALL, &resp_info, g_cfgfile);
            ioh.set_device_name(g_device.c_str(), resp_info);
        #else
            display_infotype_dialog(IORESP_ALL, &resp_info, g_cfgfile);
            set_device_name(g_device.c_str(), resp_info);
        #endif
			IDAAPI_PlanRange(0, BADADDR); // reanalyze program
		}
	}
	else
	{
		msg("ProcConf: ... failed\n");
	}
	
	return true;
}
#else
void run(int)
{
	get_cfg_filename(g_cfgfile, QMAXFILE, true);

	if (strlen(g_cfgfile) == 0)
		return;

	msg("ProcConf: loading config \"%s\"...\n", g_cfgfile);

	if ( choose_ioport_device(g_cfgfile, g_device, sizeof(g_device), NULL) )
	{
		msg("ProcConf: ... done\n");
		if (qstrcmp(g_device, "NONE") != 0)
		{
			msg("ProcConf: device chosen \"%s\"\n", g_device);

			int resp_info = IORESP_ALL;
			display_infotype_dialog(IORESP_ALL, &resp_info, g_cfgfile);

			set_device_name(g_device, resp_info);
			IDAAPI_PlanRange(0, BADADDR); // reanalyze program
		}
	}
	else
	{
		msg("ProcConf: ... failed\n");
	}
}
#endif

//--------------------------------------------------------------------------

const ioport_t *find_sym(ea_t address)
{
#if IDA_SDK_VERSION >= 700
	return find_ioport(ports, address);
#else
	return find_ioport(ports, numports, address);
#endif
}

idaapi_hook_cb_ret_t idaapi hook(void* user_data, int notification_code, va_list va)
{
	switch (notification_code) {
		case processor_t::idaapi_out_operand:
		{
		#if IDA_SDK_VERSION >= 700
			outctx_t* ctx = va_arg(va, outctx_t *);
			op_t* op = va_arg(va, op_t *);
			if (op->type == o_imm)
			{
				const ioport_t * port = find_sym(op->value);
				if ( port != NULL )
				{
					ctx->out_line(port->name.c_str(), COLOR_IMPNAME);
					return 1;
				}
			}
		#else
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
		#endif
			break;
		}
		default:
			break;
	}

	return 0;
}

//--------------------------------------------------------------------------
#if IDA_SDK_VERSION >= 760
plugmod_t *init(void)
#else
int init(void)
#endif
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
