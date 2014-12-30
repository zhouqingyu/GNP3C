#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <byteswap.h>
#include <inttypes.h>
#include <net/if.h>
#include <linux/sockios.h>

/* Define types for <linux/mii.h> and ethtool-copy.h */
/* Hack so we may include the kernel's ethtool.h */
typedef __uint8_t	u8;
typedef __uint16_t	u16;
typedef __uint32_t	u32;
typedef unsigned long long u64;

/*
 * Some <linux/mii.h> headers will include <linux/if.h> which redefines
 * ifmap, ifreq, and ifconf structures from <net/if.h>.
 * Work around for this nuisance.
 */
#define _LINUX_IF_H

#include <linux/mii.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethtool-copy.h"
#include "version.h"

enum {
	TOETOOL_SETREG			= 1024,
	TOETOOL_GETREG			= 1025,
	TOETOOL_DEVUP			= 1028,
	TOETOOL_GETMTUTAB		= 1029,
	TOETOOL_SETMTUTAB		= 1030,
	TOETOOL_GETMTU			= 1031,
	TOETOOL_SET_PM			= 1032,
	TOETOOL_GET_PM			= 1033,
	TOETOOL_SET_TCAM		= 1035,
	TOETOOL_READ_TCAM_WORD		= 1037,
	TOETOOL_GET_MEM			= 1038,
	TOETOOL_GET_SGE_CONTEXT		= 1039,
	TOETOOL_GET_SGE_DESC		= 1040,
	TOETOOL_LOAD_FW			= 1041,
	TOETOOL_SET_TRACE_FILTER        = 1044,
	TOETOOL_SET_QSET_PARAMS		= 1045,
	TOETOOL_GET_QSET_PARAMS		= 1046,
	TOETOOL_SET_QSET_NUM		= 1047,
	TOETOOL_GET_QSET_NUM		= 1048,
	TOETOOL_SET_PKTSCHED		= 1049,
	TOETOOL_SET_HW_SCHED		= 1051,
	TOETOOL_LOAD_BOOT		= 1054,
	TOETOOL_CLEAR_STATS             = 1055,
	TOETOOL_GET_UP_LA		= 1056,
	TOETOOL_GET_UP_IOQS		= 1057,
	TOETOOL_GET_TRACE_FILTER	= 1058,
	TOETOOL_GET_PKTSCHED		= 1065,

	TOETOOL_SET_FILTER		= 1060,
	TOETOOL_DEL_FILTER		= 1061,
	TOETOOL_SET_OFLD_POLICY         = 1062,

#if 0 /* Unsupported */
	TOETOOL_SETTPI			= 1026,
	TOETOOL_GETTPI			= 1027,
	TOETOOL_GET_TCAM		= 1034,
	TOETOOL_GET_TCB			= 1036,
	TOETOOL_GET_PROTO		= 1042,
	TOETOOL_SET_PROTO		= 1043,
#endif
};

#define MAX_NMTUS 16
#define TCB_SIZE 128
#define TCB_WORDS (TCB_SIZE / 4)
#define PROTO_SRAM_LINES 128
#define PROTO_SRAM_LINE_BITS 132
#define PROTO_SRAM_LINE_NIBBLES (132 / 4)
#define PROTO_SRAM_SIZE (PROTO_SRAM_LINE_NIBBLES * PROTO_SRAM_LINES / 2)
#define PROTO_SRAM_EEPROM_ADDR 4096

struct toetool_reg {
	uint32_t cmd;
	uint32_t addr;
	uint32_t val;
};

struct toetool_mtus {
	uint32_t cmd;
	uint32_t nmtus;
	uint16_t mtus[MAX_NMTUS];
};

struct toetool_pm {
	uint32_t cmd;
	uint32_t tx_pg_sz;
	uint32_t tx_num_pg;
	uint32_t rx_pg_sz;
	uint32_t rx_num_pg;
	uint32_t pm_total;
};

struct toetool_tcam {
	uint32_t cmd;
	uint32_t tcam_size;
	uint32_t nservers;
	uint32_t nroutes;
	uint32_t nfilters;
};

struct toetool_tcb {
	uint32_t cmd;
	uint32_t tcb_index;
	uint32_t tcb_data[TCB_WORDS];
};

struct reg_info {
	const char *name;
	uint16_t addr;
	uint16_t len;
};

struct toetool_tcam_word {
        uint32_t cmd;
        uint32_t addr;
        uint32_t buf[3];
};

struct toetool_mem_range {
        uint32_t cmd;
        uint32_t mem_id;
        uint32_t addr;
        uint32_t len;
        uint32_t version;
        uint8_t  buf[0];
};

struct toetool_cntxt {
	uint32_t cmd;
        uint32_t cntxt_type;
        uint32_t cntxt_id;
        uint32_t data[4];
};

struct toetool_desc {
	uint32_t cmd;
	uint32_t queue_num;
	uint32_t idx;
	uint32_t size;
	uint8_t  data[128];
};

struct toetool_proto {
	uint32_t cmd;
	uint32_t data[5 * 128];
};

struct toetool_qset_params {
	uint32_t cmd;
	uint32_t qset_idx;
	int32_t  txq_size[3];
	int32_t  rspq_size;
	int32_t  fl_size[2];
	int32_t  intr_lat;
	int32_t  polling;
	int32_t  lro;
	int32_t  cong_thres;
	int32_t  vector;
	int32_t  qnum;
};

struct toetool_trace {
	uint32_t cmd;
	uint32_t sip;
	uint32_t sip_mask;
	uint32_t dip;
	uint32_t dip_mask;
	uint16_t sport;
	uint16_t sport_mask;
	uint16_t dport;
	uint16_t dport_mask;
	uint32_t vlan:12;
	uint32_t vlan_mask:12;
	uint32_t intf:4;
	uint32_t intf_mask:4;
	uint8_t  proto;
	uint8_t  proto_mask;
	uint8_t  invert_match:1;
	uint8_t  config_tx:1;
	uint8_t  config_rx:1;
	uint8_t  trace_tx:1;
	uint8_t  trace_rx:1;
};

struct toetool_pktsched_params {
	uint32_t cmd;
	uint8_t  sched;
	uint8_t  idx;
	uint8_t  min;
	uint8_t  max;
	uint8_t  binding;
};

enum {
	PKTSCHED_PORT = 0,
	PKTSCHED_TUNNELQ =1,
};

struct ch_hw_sched {
	uint32_t cmd;
	uint8_t  sched;
	int8_t   mode;
	int8_t   channel;
	int32_t  kbps;
	int32_t  class_ipg;
	int32_t  flow_ipg;
};

struct ch_filter_tuple {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint16_t vlan:12;
	uint16_t vlan_prio:3;
};

struct ch_filter {
	uint32_t cmd;
	uint32_t filter_id;
	struct ch_filter_tuple val;
	struct ch_filter_tuple mask;
	uint16_t mac_addr_idx;
	uint8_t mac_hit:1;
	uint8_t proto:2;

	uint8_t want_filter_id:1; /* report filter TID instead of RSS hash */
	uint8_t pass:1;           /* whether to pass or drop packets */
	uint8_t rss:1;            /* use RSS or specified qset */
	uint8_t qset;
};

enum {
	LA_CTRL = 0x80,
	LA_DATA = 0x84,
	LA_ENTRIES = 2048, /* expected to cover both T3 and T4 */
};

struct toetool_la {
	uint32_t cmd;
	uint32_t stopped;
	uint32_t idx;
	uint32_t bufsize;
	uint32_t la[LA_ENTRIES];
};

enum {
	IOQ_ENTRIES = 24 /* expected to cover both T3 and T4 */
};

struct ioq_entry {
	uint32_t ioq_cp;
	uint32_t ioq_pp;
	uint32_t ioq_alen;
	uint32_t ioq_stats;
};

struct toetool_ioqs {
	uint32_t cmd;

	uint32_t ioq_rx_enable;
	uint32_t ioq_tx_enable;
	uint32_t ioq_rx_status;
	uint32_t ioq_tx_status;

	uint32_t bufsize;
	struct ioq_entry ioqs[IOQ_ENTRIES];
};

/* context types */
enum { CNTXT_TYPE_EGRESS, CNTXT_TYPE_FL, CNTXT_TYPE_RSP, CNTXT_TYPE_CQ };

/* toetool_mem_range.mem_id values */
enum { MEM_CM, MEM_PMRX, MEM_PMTX };

/* statistics categories */
enum {
	STATS_PORT  = 1 << 1,
	STATS_QUEUE = 1 << 2,
};

#include "reg_defs.c"
#if defined(CONFIG_T3_REGS)
# include "reg_defs_t3.c"
# include "reg_defs_t3b.c"
# include "reg_defs_t3c.c"
#endif

#define SIOCTOETOOL SIOCDEVPRIVATE

static const char *progname;

static int fd = -1;   /* control socket file descriptor */

static void __attribute__((noreturn)) usage(FILE *fp)
{
	fprintf(fp, "Usage: %s <interface> [operation]\n", progname);
	fprintf(fp,
		"\tclearstats [port|queue [<N>]]       clear selected statistics\n"
		"\tcontext <type> <id>                 show an SGE context\n"
		"\tdesc <qset> <queue> <idx> [<cnt>]   dump SGE descriptors\n"
		"\tfilter <idx> [<param> <val>] ...    set a filter\n"
		"\tfilter <idx> delete|clear           delete a filter\n"
		"\tloadfw <FW image>                   download firmware\n"
		"\tloadboot <boot image>               download boot image\n"
		"\tlro on|off                          enable/disable lro for all queues\n"                                
		"\tmdio <phy_addr> <mmd_addr>\n"
	        "\t     <reg_addr> [<val>]             read/write MDIO register\n"
		"\tmemdump cm|tx|rx <addr> <len>       dump a mem range\n"
		"\tmeminfo                             show memory info\n"
		"\tmtus [<mtu0>...<mtuN>]              read/write MTU table\n"
		"\tnapi on|off                         enable/disable napi for all queues\n"
		"\tpktsched port <idx> <min> <max>     set TX port scheduler params\n"
		"\tpktsched tunnelq <idx> <max>        set TX tunnelq scheduler params\n"
		"\tpktsched tx <idx>\n"
	        "\t         [<param> <val>] ...        set Tx HW scheduler\n"
		"\tpm [<TX page spec> <RX page spec>]  read/write PM config\n"
		"\tpolicy <offload policy>             set offload policy\n"
		"\tproto                               dump proto SRAM\n"
		"\tqset [<index> [<param> <val>] ...]  read/write qset parameters\n"
		"\tqsets [<# of qsets>]                read/write # of qsets\n"
		"\treg <address>[=<val>]               read/write register\n"
		"\tregdump [<module>]                  dump registers\n"
		"\ttcamdump <address> <count>          show TCAM entry\n"
		"\ttcb <index>                         read TCB\n"
		"\ttrace tx|rx|all on|off [not]\n"
	        "\t      [<param> <val>[:<mask>]] ...  write trace parameters\n"
		"\ttrace tx|rx|all                     read trace parameters\n"
		"\tioqs                                dump uP ioqs\n"
		"\tla                                  dump uP logic analyzer info\n"
		"\tup                                  activate TOE\n"
/* Unsupported
		"\ttcam [<#serv> <#routes> <#filters>] read/write TCAM config\n"
		"\ttpi <address>[=<val>]               read/write TPI register\n"
*/
		);
	exit(fp == stderr ? 1 : 0);
}

/*
 * Make an ethtool ioctl call.
 */
static int ethtool_call(const char *iff_name, void *data)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iff_name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = data;
	return ioctl(fd, SIOCETHTOOL, &ifr) < 0 ? -1 : 0;
}

/*
 * Make a TOETOOL ioctl call.
 */
static int doit(const char *iff_name, void *data)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iff_name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = data;
	return ioctl(fd, SIOCTOETOOL, &ifr) < 0 ? -1 : 0;
}

static int get_int_arg(const char *s, uint32_t *valp)
{
	char *p;

	*valp = strtoul(s, &p, 0);
	if (*p) {
		warnx("bad parameter \"%s\"", s);
		return -1;
	}
	return 0;
}

static uint32_t read_reg_ethtool(const char *iff_name, uint32_t addr)
{
	const int REGDUMP_SIZE = 4 * 1024;
	char buf[sizeof(struct ethtool_regs) + REGDUMP_SIZE];
	struct ethtool_regs *regs = (struct ethtool_regs *)buf;

	regs->cmd = ETHTOOL_GREGS;
	regs->len = REGDUMP_SIZE;
	if (ethtool_call(iff_name, regs))
		err(1, "can't read registers");
	return *((uint32_t *)(buf + sizeof(struct ethtool_regs) + addr));
}

static uint32_t read_reg(const char *iff_name, uint32_t addr)
{
	struct toetool_reg op = {
		.cmd = TOETOOL_GETREG,
		.addr = addr
	};

	if (doit(iff_name, &op) < 0) {
		if (errno != EOPNOTSUPP)
			err(1, "register read");
		return read_reg_ethtool(iff_name, addr);
	}
	return op.val;
}

static void write_reg(const char *iff_name, uint32_t addr, uint32_t val)
{
	struct toetool_reg op = {
		.cmd = TOETOOL_SETREG,
		.addr = addr,
		.val = val
	};

	if (doit(iff_name, &op) < 0)
		err(1, "register write");
}

static int register_io(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	char *p;
	uint32_t addr, val = 0, write = 0;

	if (argc != start_arg + 1) return -1;

	addr = strtoul(argv[start_arg], &p, 0);
	if (p == argv[start_arg]) return -1;
	if (*p == '=' && p[1]) {
		val = strtoul(p + 1, &p, 0);
		write = 1;
	}
	if (*p) {
		warnx("bad parameter \"%s\"", argv[start_arg]);
		return -1;
	}

	if (write)
		write_reg(iff_name, addr, val);
	else {
		val = read_reg(iff_name, addr);
		printf("%#x [%u]\n", val, val);
	}
	return 0;
}

#if 0 /* Unsupported */
static int tpi_io(int argc, char *argv[], int start_arg, const char *iff_name)
{
	char *p;
	struct toetool_reg op;

	if (argc != start_arg + 1) return -1;

	op.cmd = TOETOOL_GETTPI;
	op.addr = strtoul(argv[start_arg], &p, 0);
	if (p == argv[start_arg]) return -1;
	if (*p == '=' && p[1]) {
		op.val = strtoul(p + 1, &p, 0);
		op.cmd = TOETOOL_SETTPI;
	}
	if (*p) {
		warnx("bad parameter \"%s\"", argv[start_arg]);
		return -1;
	}

	if (doit(iff_name, &op) < 0)
		err(1, "TPI register %s",
		    op.cmd == TOETOOL_GETREG ? "read" : "write");
	if (op.cmd == TOETOOL_GETTPI)
		printf("%#x [%u]\n", op.val, op.val);
	return 0;
}
#endif

static int mdio_io(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ifreq ifr;
	struct mii_ioctl_data *p = (struct mii_ioctl_data *)(void *)&ifr.ifr_data;
	unsigned int cmd, phy_addr, reg, mmd, val;

	if (argc == start_arg + 3)
		cmd = SIOCGMIIREG;
	else if (argc == start_arg + 4)
		cmd = SIOCSMIIREG;
	else
		return -1;

	if (get_int_arg(argv[start_arg], &phy_addr) ||
	    get_int_arg(argv[start_arg + 1], &mmd) ||
	    get_int_arg(argv[start_arg + 2], &reg) ||
	    (cmd == SIOCSMIIREG && get_int_arg(argv[start_arg + 3], &val)))
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iff_name, sizeof(ifr.ifr_name) - 1);
	p->phy_id  = phy_addr | (mmd << 8);
	p->reg_num = reg;
	p->val_in  = val;

	if (ioctl(fd, cmd, &ifr) < 0)
		err(1, "MDIO %s", cmd == SIOCGMIIREG ? "read" : "write");
	if (cmd == SIOCGMIIREG)
		printf("%#x [%u]\n", p->val_out, p->val_out);
	return 0;
}

static inline uint32_t xtract(uint32_t val, int shift, int len)
{
	return (val >> shift) & ((1 << len) - 1);
}

static int dump_block_regs(const struct reg_info *reg_array, u32 *regs)
{
	uint32_t reg_val = 0; // silence compiler warning

	for ( ; reg_array->name; ++reg_array)
		if (!reg_array->len) {
			reg_val = regs[reg_array->addr / 4];
			printf("[%#5x] %-40s %#-10x [%u]\n", reg_array->addr,
			       reg_array->name, reg_val, reg_val);
		} else {
			uint32_t v = xtract(reg_val, reg_array->addr,
					    reg_array->len);

			printf("        %-40s %#-10x [%u]\n", reg_array->name,
			       v, v);
		}
	return 1;
}

static int dump_regs_t2(int argc, char *argv[], int start_arg, u32 *regs)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(sge_regs, regs);
	if (!block_name || !strcmp(block_name, "mc3"))
		match += dump_block_regs(mc3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc4"))
		match += dump_block_regs(mc4_regs, regs);
	if (!block_name || !strcmp(block_name, "tpi"))
		match += dump_block_regs(tpi_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(tp_regs, regs);
	if (!block_name || !strcmp(block_name, "rat"))
		match += dump_block_regs(rat_regs, regs);
	if (!block_name || !strcmp(block_name, "cspi"))
		match += dump_block_regs(cspi_regs, regs);
	if (!block_name || !strcmp(block_name, "espi"))
		match += dump_block_regs(espi_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp"))
		match += dump_block_regs(ulp_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(pl_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(mc5_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

#if defined(CONFIG_T3_REGS)
static int dump_regs_t3(int argc, char *argv[], int start_arg, u32 *regs,
			int is_pcie)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(sge3_regs, regs);
	if (!block_name || !strcmp(block_name, "pci"))
		match += dump_block_regs(is_pcie ? pcie0_regs : pcix1_regs,
					 regs);
	if (!block_name || !strcmp(block_name, "t3dbg"))
		match += dump_block_regs(t3dbg_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(mc7_pmrx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(mc7_pmtx_regs, regs);
	if (!block_name || !strcmp(block_name, "cm"))
		match += dump_block_regs(mc7_cm_regs, regs);
	if (!block_name || !strcmp(block_name, "cim"))
		match += dump_block_regs(cim_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(tp1_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_rx"))
		match += dump_block_regs(ulp2_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_tx"))
		match += dump_block_regs(ulp2_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(pm1_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(pm1_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "mps"))
		match += dump_block_regs(mps0_regs, regs);
	if (!block_name || !strcmp(block_name, "cplsw"))
		match += dump_block_regs(cpl_switch_regs, regs);
	if (!block_name || !strcmp(block_name, "smb"))
		match += dump_block_regs(smb0_regs, regs);
	if (!block_name || !strcmp(block_name, "i2c"))
		match += dump_block_regs(i2cm0_regs, regs);
	if (!block_name || !strcmp(block_name, "mi1"))
		match += dump_block_regs(mi1_regs, regs);
	if (!block_name || !strcmp(block_name, "sf"))
		match += dump_block_regs(sf1_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(pl3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(mc5a_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac0"))
		match += dump_block_regs(xgmac0_0_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac1"))
		match += dump_block_regs(xgmac0_1_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

static int dump_regs_t3b(int argc, char *argv[], int start_arg, u32 *regs,
			 int is_pcie)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(t3b_sge3_regs, regs);
	if (!block_name || !strcmp(block_name, "pci"))
		match += dump_block_regs(is_pcie ? t3b_pcie0_regs :
						   t3b_pcix1_regs, regs);
	if (!block_name || !strcmp(block_name, "t3dbg"))
		match += dump_block_regs(t3b_t3dbg_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3b_mc7_pmrx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3b_mc7_pmtx_regs, regs);
	if (!block_name || !strcmp(block_name, "cm"))
		match += dump_block_regs(t3b_mc7_cm_regs, regs);
	if (!block_name || !strcmp(block_name, "cim"))
		match += dump_block_regs(t3b_cim_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(t3b_tp1_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_rx"))
		match += dump_block_regs(t3b_ulp2_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_tx"))
		match += dump_block_regs(t3b_ulp2_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3b_pm1_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3b_pm1_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "mps"))
		match += dump_block_regs(t3b_mps0_regs, regs);
	if (!block_name || !strcmp(block_name, "cplsw"))
		match += dump_block_regs(t3b_cpl_switch_regs, regs);
	if (!block_name || !strcmp(block_name, "smb"))
		match += dump_block_regs(t3b_smb0_regs, regs);
	if (!block_name || !strcmp(block_name, "i2c"))
		match += dump_block_regs(t3b_i2cm0_regs, regs);
	if (!block_name || !strcmp(block_name, "mi1"))
		match += dump_block_regs(t3b_mi1_regs, regs);
	if (!block_name || !strcmp(block_name, "sf"))
		match += dump_block_regs(t3b_sf1_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(t3b_pl3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(t3b_mc5a_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac0"))
		match += dump_block_regs(t3b_xgmac0_0_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac1"))
		match += dump_block_regs(t3b_xgmac0_1_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

static int dump_regs_t3c(int argc, char *argv[], int start_arg, u32 *regs,
			 int is_pcie)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(t3c_sge3_regs, regs);
	if (!block_name || !strcmp(block_name, "pci"))
		match += dump_block_regs(is_pcie ? t3c_pcie0_regs :
						   t3c_pcix1_regs, regs);
	if (!block_name || !strcmp(block_name, "t3dbg"))
		match += dump_block_regs(t3c_t3dbg_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3c_mc7_pmrx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3c_mc7_pmtx_regs, regs);
	if (!block_name || !strcmp(block_name, "cm"))
		match += dump_block_regs(t3c_mc7_cm_regs, regs);
	if (!block_name || !strcmp(block_name, "cim"))
		match += dump_block_regs(t3c_cim_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(t3c_tp1_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_rx"))
		match += dump_block_regs(t3c_ulp2_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_tx"))
		match += dump_block_regs(t3c_ulp2_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3c_pm1_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3c_pm1_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "mps"))
		match += dump_block_regs(t3c_mps0_regs, regs);
	if (!block_name || !strcmp(block_name, "cplsw"))
		match += dump_block_regs(t3c_cpl_switch_regs, regs);
	if (!block_name || !strcmp(block_name, "smb"))
		match += dump_block_regs(t3c_smb0_regs, regs);
	if (!block_name || !strcmp(block_name, "i2c"))
		match += dump_block_regs(t3c_i2cm0_regs, regs);
	if (!block_name || !strcmp(block_name, "mi1"))
		match += dump_block_regs(t3c_mi1_regs, regs);
	if (!block_name || !strcmp(block_name, "sf"))
		match += dump_block_regs(t3c_sf1_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(t3c_pl3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(t3c_mc5a_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac0"))
		match += dump_block_regs(t3c_xgmac0_0_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac1"))
		match += dump_block_regs(t3c_xgmac0_1_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}
#endif

static int dump_regs(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	const int REGDUMP_SIZE = 4 * 1024;

	int vers, revision, is_pcie;
	char buf[sizeof(struct ethtool_regs) + REGDUMP_SIZE];
	struct ethtool_regs *regs = (struct ethtool_regs *)buf;

	regs->cmd = ETHTOOL_GREGS;
	regs->len = REGDUMP_SIZE;
	if (ethtool_call(iff_name, regs))
		err(1, "can't read registers");

	vers = regs->version & 0x3ff;
	revision = (regs->version >> 10) & 0x3f;
	is_pcie = (regs->version & 0x80000000) != 0;

	if (vers <= 2)
		return dump_regs_t2(argc, argv, start_arg, (u32 *)regs->data);
#if defined(CONFIG_T3_REGS)
	if (vers == 3) {
		if (revision == 0)
			return dump_regs_t3(argc, argv, start_arg,
					    (u32 *)regs->data, is_pcie);
		if (revision == 2 || revision == 3)
			return dump_regs_t3b(argc, argv, start_arg,
					     (u32 *)regs->data, is_pcie);
		if (revision == 4)
			return dump_regs_t3c(argc, argv, start_arg,
					     (u32 *)regs->data, is_pcie);
	}
#endif
	errx(1, "unknown card type %d, rev %d", vers, revision);
	return 0;
}

static int t3_meminfo(const u32 *regs)
{
	enum {
		SG_EGR_CNTX_BADDR = 0x58,
		SG_CQ_CONTEXT_BADDR = 0x6c,
		CIM_SDRAM_BASE_ADDR = 0x28c,
		CIM_SDRAM_ADDR_SIZE = 0x290,
		TP_CMM_MM_BASE = 0x314,
		TP_CMM_TIMER_BASE = 0x318,
		TP_CMM_MM_RX_FLST_BASE = 0x460,
		TP_CMM_MM_TX_FLST_BASE = 0x464,
		TP_CMM_MM_PS_FLST_BASE = 0x468,
		ULPRX_ISCSI_LLIMIT = 0x50c,
		ULPRX_ISCSI_ULIMIT = 0x510,
		ULPRX_TDDP_LLIMIT = 0x51c,
		ULPRX_TDDP_ULIMIT = 0x520,
		ULPRX_STAG_LLIMIT = 0x52c,
		ULPRX_STAG_ULIMIT = 0x530,
		ULPRX_RQ_LLIMIT = 0x534,
		ULPRX_RQ_ULIMIT = 0x538,
		ULPRX_PBL_LLIMIT = 0x53c,
		ULPRX_PBL_ULIMIT = 0x540,
	};

	unsigned int egr_cntxt = regs[SG_EGR_CNTX_BADDR / 4],
		     cq_cntxt = regs[SG_CQ_CONTEXT_BADDR / 4],
		     timers = regs[TP_CMM_TIMER_BASE / 4] & 0xfffffff,
		     pstructs = regs[TP_CMM_MM_BASE / 4],
		     pstruct_fl = regs[TP_CMM_MM_PS_FLST_BASE / 4],
		     rx_fl = regs[TP_CMM_MM_RX_FLST_BASE / 4],
		     tx_fl = regs[TP_CMM_MM_TX_FLST_BASE / 4],
		     cim_base = regs[CIM_SDRAM_BASE_ADDR / 4],
		     cim_size = regs[CIM_SDRAM_ADDR_SIZE / 4];
	unsigned int iscsi_ll = regs[ULPRX_ISCSI_LLIMIT / 4],
		     iscsi_ul = regs[ULPRX_ISCSI_ULIMIT / 4],
		     tddp_ll = regs[ULPRX_TDDP_LLIMIT / 4],
		     tddp_ul = regs[ULPRX_TDDP_ULIMIT / 4],
		     stag_ll = regs[ULPRX_STAG_LLIMIT / 4],
		     stag_ul = regs[ULPRX_STAG_ULIMIT / 4],
		     rq_ll = regs[ULPRX_RQ_LLIMIT / 4],
		     rq_ul = regs[ULPRX_RQ_ULIMIT / 4],
		     pbl_ll = regs[ULPRX_PBL_LLIMIT / 4],
		     pbl_ul = regs[ULPRX_PBL_ULIMIT / 4];

	printf("CM memory map:\n");
	printf("  TCB region:      0x%08x - 0x%08x [%u]\n", 0, egr_cntxt - 1,
	       egr_cntxt);
	printf("  Egress contexts: 0x%08x - 0x%08x [%u]\n", egr_cntxt,
	       cq_cntxt - 1, cq_cntxt - egr_cntxt);
	printf("  CQ contexts:     0x%08x - 0x%08x [%u]\n", cq_cntxt,
	       timers - 1, timers - cq_cntxt);
	printf("  Timers:          0x%08x - 0x%08x [%u]\n", timers,
	       pstructs - 1, pstructs - timers);
	printf("  Pstructs:        0x%08x - 0x%08x [%u]\n", pstructs,
	       pstruct_fl - 1, pstruct_fl - pstructs);
	printf("  Pstruct FL:      0x%08x - 0x%08x [%u]\n", pstruct_fl,
	       rx_fl - 1, rx_fl - pstruct_fl);
	printf("  Rx FL:           0x%08x - 0x%08x [%u]\n", rx_fl, tx_fl - 1,
	       tx_fl - rx_fl);
	printf("  Tx FL:           0x%08x - 0x%08x [%u]\n", tx_fl, cim_base - 1,
	       cim_base - tx_fl);
	printf("  uP RAM:          0x%08x - 0x%08x [%u]\n", cim_base,
	       cim_base + cim_size - 1, cim_size);

	printf("\nPMRX memory map:\n");
	printf("  iSCSI region:    0x%08x - 0x%08x [%u]\n", iscsi_ll, iscsi_ul,
	       iscsi_ul - iscsi_ll + 1);
	printf("  TCP DDP region:  0x%08x - 0x%08x [%u]\n", tddp_ll, tddp_ul,
	       tddp_ul - tddp_ll + 1);
	printf("  TPT region:      0x%08x - 0x%08x [%u]\n", stag_ll, stag_ul,
	       stag_ul - stag_ll + 1);
	printf("  RQ region:       0x%08x - 0x%08x [%u]\n", rq_ll, rq_ul,
	       rq_ul - rq_ll + 1);
	printf("  PBL region:      0x%08x - 0x%08x [%u]\n", pbl_ll, pbl_ul,
	       pbl_ul - pbl_ll + 1);
	return 0;
}

static int meminfo(int argc, char *argv[], int start_arg, const char *iff_name)
{
	const int REGDUMP_SIZE = 4 * 1024;

	int vers;
	char buf[sizeof(struct ethtool_regs) + REGDUMP_SIZE];
	struct ethtool_regs *regs = (struct ethtool_regs *)buf;

	regs->cmd = ETHTOOL_GREGS;
	regs->len = REGDUMP_SIZE;
	if (ethtool_call(iff_name, regs))
		err(1, "can't read registers");

	vers = regs->version & 0x3ff;
	if (vers == 3)
		return t3_meminfo((u32 *)regs->data);

	errx(1, "unknown card type %d", vers);
	return 0;
}

static int device_up(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	uint32_t op = TOETOOL_DEVUP;

	if (argc != start_arg) return -1;
	if (doit(iff_name, &op) < 0)
		err(1, "up");
	return 0;
}

static int mtu_tab_op(int argc, char *argv[], int start_arg,
		      const char *iff_name)
{
	struct toetool_mtus op;
	int i;

	if (argc == start_arg) {
		op.cmd = TOETOOL_GETMTUTAB;
		op.nmtus = MAX_NMTUS;

		if (doit(iff_name, &op) < 0)
			err(1, "get MTU table");
		for (i = 0; i < op.nmtus; ++i)
			printf("%u ", op.mtus[i]);
		printf("\n");
	} else if (argc <= start_arg + MAX_NMTUS) {
		op.cmd = TOETOOL_SETMTUTAB;
		op.nmtus = argc - start_arg;

		for (i = 0; i < op.nmtus; ++i) {
			char *p;
			unsigned long m = strtoul(argv[start_arg + i], &p, 0);

			if (*p || m > 9600) {
				warnx("bad parameter \"%s\"",
				      argv[start_arg + i]);
				return -1;
			}
			if (i && m < op.mtus[i - 1])
				errx(1, "MTUs must be in ascending order");
			op.mtus[i] = m;
		}
		if (doit(iff_name, &op) < 0)
			err(1, "set MTU table");
	} else
		return -1;

	return 0;
}

static void show_egress_cntxt(u32 data[])
{
	printf("credits:      %u\n", data[0] & 0x7fff);
	printf("GTS:          %u\n", (data[0] >> 15) & 1);
	printf("index:        %u\n", data[0] >> 16);
	printf("queue size:   %u\n", data[1] & 0xffff);
	printf("base address: 0x%llx\n",
	       ((data[1] >> 16) | ((u64)data[2] << 16) |
	       (((u64)data[3] & 0xf) << 48)) << 12);
	printf("rsp queue #:  %u\n", (data[3] >> 4) & 7);
	printf("cmd queue #:  %u\n", (data[3] >> 7) & 1);
	printf("TUN:          %u\n", (data[3] >> 8) & 1);
	printf("TOE:          %u\n", (data[3] >> 9) & 1);
	printf("generation:   %u\n", (data[3] >> 10) & 1);
	printf("uP token:     %u\n", (data[3] >> 11) & 0xfffff);
	printf("valid:        %u\n", (data[3] >> 31) & 1);
}

static void show_fl_cntxt(u32 data[])
{
	printf("base address: 0x%llx\n",
	       ((u64)data[0] | ((u64)data[1] & 0xfffff) << 32) << 12);
	printf("index:        %u\n", (data[1] >> 20) | ((data[2] & 0xf) << 12));
	printf("queue size:   %u\n", (data[2] >> 4) & 0xffff);
	printf("generation:   %u\n", (data[2] >> 20) & 1);
	printf("entry size:   %u\n",
	       (data[2] >> 21) | (data[3] & 0x1fffff) << 11);
	printf("congest thr:  %u\n", (data[3] >> 21) & 0x3ff);
	printf("GTS:          %u\n", (data[3] >> 31) & 1);
}

static void show_response_cntxt(u32 data[])
{
	printf("index:        %u\n", data[0] & 0xffff);
	printf("size:         %u\n", data[0] >> 16);
	printf("base address: 0x%llx\n",
	       ((u64)data[1] | ((u64)data[2] & 0xfffff) << 32) << 12);
	printf("MSI-X/RspQ:   %u\n", (data[2] >> 20) & 0x3f);
	printf("intr enable:  %u\n", (data[2] >> 26) & 1);
	printf("intr armed:   %u\n", (data[2] >> 27) & 1);
	printf("generation:   %u\n", (data[2] >> 28) & 1);
	printf("CQ mode:      %u\n", (data[2] >> 31) & 1);
	printf("FL threshold: %u\n", data[3]);
}

static void show_cq_cntxt(u32 data[])
{
	printf("index:            %u\n", data[0] & 0xffff);
	printf("size:             %u\n", data[0] >> 16);
	printf("base address:     0x%llx\n",
	       ((u64)data[1] | ((u64)data[2] & 0xfffff) << 32) << 12);
	printf("rsp queue #:      %u\n", (data[2] >> 20) & 0x3f);
	printf("AN:               %u\n", (data[2] >> 26) & 1);
	printf("armed:            %u\n", (data[2] >> 27) & 1);
	printf("ANS:              %u\n", (data[2] >> 28) & 1);
	printf("generation:       %u\n", (data[2] >> 29) & 1);
	printf("overflow mode:    %u\n", (data[2] >> 31) & 1);
	printf("credits:          %u\n", data[3] & 0xffff);
	printf("credit threshold: %u\n", data[3] >> 16);
}

static int get_sge_context(int argc, char *argv[], int start_arg,
			   const char *iff_name)
{
	struct toetool_cntxt op;

	if (argc != start_arg + 2) return -1;

	if (!strcmp(argv[start_arg], "egress"))
		op.cntxt_type = CNTXT_TYPE_EGRESS;
	else if (!strcmp(argv[start_arg], "fl"))
		op.cntxt_type = CNTXT_TYPE_FL;
	else if (!strcmp(argv[start_arg], "response"))
		op.cntxt_type = CNTXT_TYPE_RSP;
	else if (!strcmp(argv[start_arg], "cq"))
		op.cntxt_type = CNTXT_TYPE_CQ;
	else {
		warnx("unknown context type \"%s\"; known types are egress, "
		      "fl, cq, and response", argv[start_arg]);
		return -1;
	}

	if (get_int_arg(argv[start_arg + 1], &op.cntxt_id))
		return -1;

	op.cmd = TOETOOL_GET_SGE_CONTEXT;
	if (doit(iff_name, &op) < 0)
		err(1, "get SGE context");

	if (!strcmp(argv[start_arg], "egress"))
		show_egress_cntxt(op.data);
	else if (!strcmp(argv[start_arg], "fl"))
		show_fl_cntxt(op.data);
	else if (!strcmp(argv[start_arg], "response"))
		show_response_cntxt(op.data);
	else if (!strcmp(argv[start_arg], "cq"))
		show_cq_cntxt(op.data);
	return 0;
}

#if __BYTE_ORDER == __BIG_ENDIAN
# define ntohll(n) (n)
#else
# define ntohll(n) bswap_64(n)
#endif

static int get_sge_desc(int argc, char *argv[], int start_arg,
			const char *iff_name)
{
	u64 *p, wr_hdr;
	unsigned int n = 1, qset, qnum;
	struct toetool_desc op;

	if (argc != start_arg + 3 && argc != start_arg + 4)
		return -1;

	if (get_int_arg(argv[start_arg], &qset) ||
	    get_int_arg(argv[start_arg + 1], &qnum) ||
	    get_int_arg(argv[start_arg + 2], &op.idx))
		return -1;

	if (argc == start_arg + 4 && get_int_arg(argv[start_arg + 3], &n))
		return -1;

	if (qnum > 5)
		errx(1, "invalid queue number %d, range is 0..5", qnum);

	op.cmd = TOETOOL_GET_SGE_DESC;
	op.queue_num = qset * 6 + qnum;

	for (; n--; op.idx++) {
		if (doit(iff_name, &op) < 0)
			err(1, "get SGE descriptor");

		p = (u64 *)op.data;
		wr_hdr = ntohll(*p);
		printf("Descriptor %u: cmd %u, TID %u, %s%s%s%s%u flits\n",
		       op.idx, (unsigned int)(wr_hdr >> 56),
		       ((unsigned int)wr_hdr >> 8) & 0xfffff,
		       ((wr_hdr >> 55) & 1) ? "SOP, " : "",
		       ((wr_hdr >> 54) & 1) ? "EOP, " : "",
		       ((wr_hdr >> 53) & 1) ? "COMPL, " : "",
		       ((wr_hdr >> 52) & 1) ? "SGL, " : "",
		       (unsigned int)wr_hdr & 0xff);

		for (; op.size; p++, op.size -= sizeof(u64))
			printf("%016" PRIx64 "%c", ntohll(*p),
			       op.size % 32 == 8 ? '\n' : ' ');
	}
	return 0;
}

static int get_tcb2(int argc, char *argv[], int start_arg, const char *iff_name)
{
	uint64_t *d;
	unsigned int i;
	unsigned int tcb_idx;
	struct toetool_mem_range *op;

	if (argc != start_arg + 1)
		return -1;

	if (get_int_arg(argv[start_arg], &tcb_idx))
		return -1;

	op = malloc(sizeof(*op) + TCB_SIZE);
	if (!op)
		err(1, "get TCB");

	op->cmd    = TOETOOL_GET_MEM;
	op->mem_id = MEM_CM;
	op->addr   = tcb_idx * TCB_SIZE;
	op->len    = TCB_SIZE;

	if (doit(iff_name, op) < 0)
		err(1, "get TCB");

	for (d = (uint64_t *)op->buf, i = 0; i < TCB_SIZE / 32; i++) {
		printf("%2u:", i);
		printf(" %08x %08x %08x %08x", (uint32_t)d[1],
		       (uint32_t)(d[1] >> 32), (uint32_t)d[0],
		       (uint32_t)(d[0] >> 32));
		d += 2;
		printf(" %08x %08x %08x %08x\n", (uint32_t)d[1],
		       (uint32_t)(d[1] >> 32), (uint32_t)d[0],
		       (uint32_t)(d[0] >> 32));
		d += 2;
	}
	free(op);
	return 0;
}

#if 0 /* Unsupported */
static int get_tcb(int argc, char *argv[], int start_arg, const char *iff_name)
{
	int i;
	uint32_t *d;
	struct toetool_tcb op;

	if (argc != start_arg + 1) return -1;

	op.cmd = TOETOOL_GET_TCB;
	if (get_int_arg(argv[start_arg], &op.tcb_index))
		return -1;

	/*
	 * If this operation isn't directly supported by the driver we may
	 * still be able to read TCBs using the generic memory dump operation.
	 */
	if (doit(iff_name, &op) < 0) {
		if (errno != EOPNOTSUPP)
			err(1, "get TCB");
		return get_tcb2(op.tcb_index, iff_name);
	}

	for (d = op.tcb_data, i = 0; i < TCB_WORDS; i += 8) {
		int j;

		printf("%2u:", 4 * i);
		for (j = 0; j < 8; ++j)
			printf(" %08x", *d++);
		printf("\n");
	}
	return 0;
}
#endif

#ifdef WRC
/*
 * The following defines, typedefs and structures are defined in the FW and
 * should be exported instead of being redefined here (and kept up in sync).
 * We'll fix this in the next round of FW cleanup.
 */
#define CM_WRCONTEXT_BASE       0x20300000
#define CM_WRCONTEXT_OFFSET	0x300000
#define WRC_SIZE                (FW_WR_SIZE * (2 + FW_WR_NUM) + 32 + 4 * 128)
#define FW_WR_SIZE	128
#define FW_WR_NUM	16
#define FBUF_SIZE	(FW_WR_SIZE * FW_WR_NUM)
#define FBUF_WRAP_SIZE	128
#define FBUF_WRAP_FSZ	(FBUF_WRAP_SZ >> 3)
#define MEM_CM_WRC_SIZE  WRC_SIZE

typedef char 			_s8;
typedef short 			_s16;
typedef int 			_s32;
typedef long long 		_s64;
typedef unsigned char           _u8;
typedef unsigned short          _u16;
typedef unsigned int            _u32;
typedef unsigned long long      _u64;

enum fw_ri_mpa_attrs {
	FW_RI_MPA_RX_MARKER_ENABLE = 0x1,
	FW_RI_MPA_TX_MARKER_ENABLE = 0x2,
	FW_RI_MPA_CRC_ENABLE	= 0x4,
	FW_RI_MPA_IETF_ENABLE	= 0x8
} __attribute__ ((packed));

enum fw_ri_qp_caps {
	FW_RI_QP_RDMA_READ_ENABLE = 0x01,
	FW_RI_QP_RDMA_WRITE_ENABLE = 0x02,
	FW_RI_QP_BIND_ENABLE	= 0x04,
	FW_RI_QP_FAST_REGISTER_ENABLE = 0x08,
	FW_RI_QP_STAG0_ENABLE	= 0x10
} __attribute__ ((packed));

enum wrc_state {
	WRC_STATE_CLOSED,
	WRC_STATE_ABORTED,
	WRC_STATE_HALFCLOSED,
	WRC_STATE_TOE_ESTABLISHED,
	WRC_STATE_RDMA_TX_DATA_PEND,
	WRC_STATE_RDMA_PEND,
	WRC_STATE_RDMA_ESTABLISHED,
};

enum ack_mode {
	ACK_MODE_TIMER,
	ACK_MODE_TIMER_PENDING,
	ACK_MODE_IMMEDIATE
} __attribute__ ((packed));

enum timer_state {
	TIMER_IDLE,			/* No Timer pending */
	TIMER_DELETED,			/* Timer has been deleted, but is still
					 * in the TOETIMERF
					 */
	TIMER_ADDED,			/* Timer added and in the TOETIMERF */
} __attribute__ ((packed));

struct _wr {
	_u32 a;
	_u32 b;
};

struct fbuf {
	_u32 	pp;			/* fifo producer pointer */
	_u32	cp;			/* fifo consumer pointer */
	_s32	num_bytes;		/* num bytes stored in the fbuf */
	char	bufferb[FBUF_SIZE]; 	/* buffer space in bytes */
	char	_wrap[FBUF_WRAP_SIZE];	/* wrap buffer size*/
};
struct wrc {
	_u32	wrc_tid;
	_u16	wrc_flags;
	_u8	wrc_state;
	_u8	wrc_credits;

	/* IO */
	_u16	wrc_sge_ec;
	_u8	wrc_sge_respQ;
	_u8	wrc_port;
	_u8	wrc_ulp;

	_u8	wrc_coherency_counter;

	/* REASSEMBLY */
	_u8	wrc_frag_len;
	_u8	wrc_frag_credits;
	_u32	wrc_frag;

	union {
		struct {

			/* TOE */
			_u8	aborted;
			_u8	wrc_num_tx_pages;
			_u8	wrc_max_tx_pages;
			_u8	wrc_trace_idx;
			_u32 	wrc_snd_nxt;
			_u32 	wrc_snd_max;
			_u32 	wrc_snd_una;
			_u32	wrc_snd_iss;

			/* RI */
			_u32	wrc_pdid;
			_u32	wrc_scqid;
			_u32	wrc_rcqid;
			_u32	wrc_rq_addr_32a;
			_u16	wrc_rq_size;
			_u16	wrc_rq_wr_idx;
			enum fw_ri_mpa_attrs wrc_mpaattrs;
			enum fw_ri_qp_caps wrc_qpcaps;
			_u16	wrc_mulpdu_tagged;
			_u16	wrc_mulpdu_untagged;
			_u16	wrc_ord_max;
			_u16	wrc_ird_max;
			_u16	wrc_ord;
			_u16	wrc_ird;
			_u16	wrc_markeroffset;
			_u32	wrc_msn_send;
			_u32	wrc_msn_rdma_read;
			_u32	wrc_msn_rdma_read_req;
			_u16	wrc_rdma_read_req_err;
			_u8	wrc_ack_mode;
			_u8	wrc_sge_ec_credits;
			_u16	wrc_maxiolen_tagged;
			_u16	wrc_maxiolen_untagged;
			_u32	wrc_mo;
			_u8	wrc_ack_tx_pages; // move me up
			enum timer_state wrc_timer; // move me up

		} toe_ri;

		struct {

		} ipmi;

		struct {
			_u32	wrc_pad2[24];
		} pad;
	} u __attribute__ ((packed));

	/* BUFFERING */
	struct fbuf wrc_fbuf __attribute__ ((packed));
};
#define wrc_aborted u.toe_ri.aborted
#define wrc_num_tx_pages u.toe_ri.wrc_num_tx_pages
#define wrc_max_tx_pages u.toe_ri.wrc_max_tx_pages
#define wrc_trace_idx u.toe_ri.wrc_trace_idx
#define wrc_snd_nxt u.toe_ri.wrc_snd_nxt
#define wrc_snd_max u.toe_ri.wrc_snd_max
#define wrc_snd_una u.toe_ri.wrc_snd_una
#define wrc_snd_iss u.toe_ri.wrc_snd_iss
#define wrc_pdid u.toe_ri.wrc_pdid
#define wrc_scqid u.toe_ri.wrc_scqid
#define wrc_rcqid u.toe_ri.wrc_rcqid
#define wrc_rq_addr_32a u.toe_ri.wrc_rq_addr_32a
#define wrc_rq_size u.toe_ri.wrc_rq_size
#define wrc_rq_wr_idx u.toe_ri.wrc_rq_wr_idx
#define wrc_mpaattrs u.toe_ri.wrc_mpaattrs
#define wrc_qpcaps u.toe_ri.wrc_qpcaps
#define wrc_mulpdu_tagged u.toe_ri.wrc_mulpdu_tagged
#define wrc_mulpdu_untagged u.toe_ri.wrc_mulpdu_untagged
#define wrc_ord_max u.toe_ri.wrc_ord_max
#define wrc_ird_max u.toe_ri.wrc_ird_max
#define wrc_ord u.toe_ri.wrc_ord
#define wrc_ird u.toe_ri.wrc_ird
#define wrc_markeroffset u.toe_ri.wrc_markeroffset
#define wrc_msn_send u.toe_ri.wrc_msn_send
#define wrc_msn_rdma_read u.toe_ri.wrc_msn_rdma_read
#define wrc_msn_rdma_read_req u.toe_ri.wrc_msn_rdma_read_req
#define wrc_rdma_read_req_err u.toe_ri.wrc_rdma_read_req_err
#define wrc_ack_mode u.toe_ri.wrc_ack_mode
#define wrc_sge_ec_credits u.toe_ri.wrc_sge_ec_credits
#define wrc_maxiolen_tagged u.toe_ri.wrc_maxiolen_tagged
#define wrc_maxiolen_untagged u.toe_ri.wrc_maxiolen_untagged
#define wrc_mo u.toe_ri.wrc_mo
#define wrc_ack_tx_pages u.toe_ri.wrc_ack_tx_pages
#define wrc_timer u.toe_ri.wrc_timer

static void print_wrc_field(char *field, unsigned int value, unsigned int size)
{
	switch(size) {
	case 1:
		printf("  1 %s: 0x%02x (%u)\n", field, value, value);
		break;
	case 2: {
		unsigned short host_value = ntohs(value);
		printf("  2 %s: 0x%04x (%u)\n", field, host_value, host_value);
		break;
	}
	case 4: {
		unsigned int host_value = ntohl(value);
		printf("  4 %s: 0x%08x (%u)\n", field, host_value, host_value);
		break;
	}
	default:
		printf("  unknown size %u for field %s\n", size, field);
	}
}

#define P(field)  print_wrc_field(#field, p->wrc_ ## field, sizeof (p->wrc_ ## field))

static void print_wrc(unsigned int wrc_idx, struct wrc *p)
{
	u32 *buf = (u32 *)p;
	unsigned int i, j;

	printf("WRC STATE (raw)\n");
	for (i = 0; i < 32;) {
		printf("[%08x]:", 0x20300000 + wrc_idx * MEM_CM_WRC_SIZE + i * 4);
		for (j = 0; j < 8; j++) {
			printf(" %08x ", htonl(buf[i++]));
		}
		printf("\n");
	}
	printf("WRC BASIC\n");
	P(tid); P(flags); P(state); P(credits);
	printf("WRC IO\n");
	P(sge_ec); P(sge_respQ); P(port); P(ulp); P(coherency_counter);
	printf("WRC REASSEMBLY\n");
	P(frag_len); P(frag_credits); P(frag);
	printf("WRC TOE\n");
	P(aborted); P(num_tx_pages); P(max_tx_pages); P(ack_tx_pages); P(timer); P(trace_idx); P(snd_nxt);
	P(snd_max); P(snd_una); P(snd_iss);
	printf("WRC RI\n");
	P(pdid); P(scqid); P(rcqid); P(rq_addr_32a); P(rq_size); P(rq_wr_idx);
	P(mpaattrs); P(qpcaps); P(mulpdu_tagged); P(mulpdu_untagged); P(ord_max);
	P(ird_max); P(ord); P(ird); P(markeroffset); P(msn_send); P(msn_rdma_read);
	P(msn_rdma_read_req); P(rdma_read_req_err); P(ack_mode);
	P(sge_ec_credits); P(maxiolen_tagged); P(maxiolen_untagged); P(mo);
	printf("WRC BUFFERING\n");
	printf("  4 fbuf.pp: 0x%08x (%u)\n", htonl(p->wrc_fbuf.pp),  htonl(p->wrc_fbuf.pp));
	printf("  4 fbuf.cp: 0x%08x (%u)\n",  htonl(p->wrc_fbuf.cp),  htonl(p->wrc_fbuf.cp));
	printf("  4 fbuf.num_bytes: 0x%08x (%d)\n",  htonl(p->wrc_fbuf.num_bytes),  htonl(p->wrc_fbuf.num_bytes));
	printf("WRC BUFFER (raw)\n");
	for (i = 32; i < (FBUF_SIZE + FBUF_WRAP_SIZE) / 4;) {
		printf("[%08x]:", 0x20300000 + wrc_idx * MEM_CM_WRC_SIZE + i * 4);
		for (j = 0; j < 4; j++) {
			printf(" %016lx", ((unsigned long)htonl(buf[i++]) << 32) | htonl(buf[i++]) );
		}
		printf("\n");
	}
}

#undef P

#define P(field)  print_sizeof(#field, ##field, sizeof (p->##field))

struct history_e {
	_u32 wr_addr;
	_u32 debug;
	_u64 wr_flit0;
	_u64 wr_flit1;
	_u64 wr_flit2;
};

static void print_wrc_zero(unsigned int wrc_idx, struct wrc *p)
{
	uint32_t *buf =
	   (uint32_t *)((unsigned long)p + FW_WR_SIZE * (2 + FW_WR_NUM));
	unsigned int i;

	printf("WRC ZERO\n");
	printf("[%08x]:", CM_WRCONTEXT_BASE + wrc_idx * MEM_CM_WRC_SIZE +
	       FW_WR_SIZE * (2 + FW_WR_NUM));
	for (i = 0; i < 4;)
		printf(" %08x%08x", htonl(buf[i]), htonl(buf[i++]));
	printf("\n");
}

static void print_wrc_history(struct wrc *p)
{
	unsigned int i, idx;
	struct history_e *e =
	    (struct history_e *)((unsigned long)p + FW_WR_SIZE *
				 (2 + FW_WR_NUM) + 32);
	printf("WRC WR HISTORY, idx %u\n", p->wrc_trace_idx);
	idx = p->wrc_trace_idx;
	for (i = 0; i < 16; i++) {
		printf("%02u: %08x %08x %08x%08x %08x%08x %08x%08x\n", idx,
		       htonl(e[idx].wr_addr), htonl(e[idx].debug),
		       htonl(e[idx].wr_flit0 & 0xFFFFFFFF),
		       htonl(e[idx].wr_flit0 >> 32),
		       htonl(e[idx].wr_flit1 & 0xFFFFFFFF),
		       htonl(e[idx].wr_flit1 >> 32),
		       htonl(e[idx].wr_flit2 & 0xFFFFFFFF),
		       htonl(e[idx].wr_flit2 >> 32));
		idx = (idx - 1) & 0xF;
	}
}

static int get_wrc(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct toetool_mem_range *op;
	uint64_t *p;
	uint32_t *buf;
	unsigned int idx, i = 0;

	if (argc != start_arg + 1)
		return -1;

	if (get_int_arg(argv[start_arg], &idx))
		return -1;

	op = malloc(sizeof(*op) + MEM_CM_WRC_SIZE);
	if (!op)
		err(1, "get_wrc: malloc failed");

	op->cmd    = TOETOOL_GET_MEM;
	op->mem_id = MEM_CM;
	op->addr   = read_reg(iff_name, 0x28c) + CM_WRCONTEXT_OFFSET +
			      idx * MEM_CM_WRC_SIZE;
	op->len    = MEM_CM_WRC_SIZE;
	buf = (uint32_t *)op->buf;

	if (doit(iff_name, op) < 0)
		err(1, "get_wrc");

	/* driver manges with the data... put it back into the the FW's view
	 */
	for (p = (uint64_t *)op->buf;
	         p < (uint64_t *)(op->buf + MEM_CM_WRC_SIZE); p++) {
		uint64_t flit = *p;
		buf[i++] = htonl((uint32_t)(flit >> 32));
		buf[i++] = htonl((uint32_t)flit);
	}

	print_wrc(idx, (struct wrc *)op->buf);
	print_wrc_zero(idx, (struct wrc *)op->buf);
	print_wrc_history((struct wrc *)op->buf);

	free(op);
	return 0;
}
#endif

static int get_pm_page_spec(const char *s, unsigned int *page_size,
			    unsigned int *num_pages)
{
	char *p;
	unsigned long val;

	val = strtoul(s, &p, 0);
	if (p == s) return -1;
	if (*p == 'x' && p[1]) {
		*num_pages = val;
		*page_size = strtoul(p + 1, &p, 0);
	} else {
		*num_pages = -1;
		*page_size = val;
	}
	*page_size <<= 10;     // KB -> bytes
	return *p;
}

static int conf_pm(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct toetool_pm op;

	if (argc == start_arg) {
	 	op.cmd = TOETOOL_GET_PM;
		if (doit(iff_name, &op) < 0)
			err(1, "read pm config");
		printf("%ux%uKB TX pages, %ux%uKB RX pages, %uKB total memory\n",
		       op.tx_num_pg, op.tx_pg_sz >> 10, op.rx_num_pg,
		       op.rx_pg_sz >> 10, op.pm_total >> 10);
		return 0;
	}

	if (argc != start_arg + 2) return -1;

	if (get_pm_page_spec(argv[start_arg], &op.tx_pg_sz, &op.tx_num_pg)) {
		warnx("bad parameter \"%s\"", argv[start_arg]);
		return -1;
	}
	if (get_pm_page_spec(argv[start_arg + 1], &op.rx_pg_sz,
			     &op.rx_num_pg)) {
		warnx("bad parameter \"%s\"", argv[start_arg + 1]);
		return -1;
	}
	op.cmd = TOETOOL_SET_PM;
	if (doit(iff_name, &op) < 0)
		err(1, "pm config");
	return 0;
}

#if 0 /* Unsupported */
static int conf_tcam(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	struct toetool_tcam op;

	if (argc == start_arg) {
		op.cmd = TOETOOL_GET_TCAM;
		op.nfilters = 0;
		if (doit(iff_name, &op) < 0)
			err(1, "read tcam config");
		printf("%u total entries, %u servers, %u filters, %u routes\n",
		       op.tcam_size, op.nservers, op.nfilters, op.nroutes);
		return 0;
	}

	if (argc != start_arg + 3) return -1;

	if (get_int_arg(argv[start_arg], &op.nservers) ||
	    get_int_arg(argv[start_arg + 1], &op.nroutes) ||
	    get_int_arg(argv[start_arg + 2], &op.nfilters))
		return -1;
	op.cmd = TOETOOL_SET_TCAM;
	if (doit(iff_name, &op) < 0)
		err(1, "tcam config");
	return 0;
}
#endif

static int dump_tcam(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	unsigned int nwords;
	struct toetool_tcam_word op;

	if (argc != start_arg + 2) return -1;

	if (get_int_arg(argv[start_arg], &op.addr) ||
	    get_int_arg(argv[start_arg + 1], &nwords))
		return -1;
	op.cmd = TOETOOL_READ_TCAM_WORD;

	while (nwords--) {
		if (doit(iff_name, &op) < 0)
			err(1, "tcam dump");

		printf("0x%08x: 0x%02x 0x%08x 0x%08x\n", op.addr,
		       op.buf[0] & 0xff, op.buf[1], op.buf[2]);
		op.addr++;
	}
	return 0;
}

static void hexdump_8b(unsigned int start, uint64_t *data, unsigned int len)
{
	int i;

	while (len) {
		printf("0x%08x:", start);
		for (i = 0; i < 4 && len; ++i, --len)
			printf(" %016llx", (unsigned long long)*data++);
		printf("\n");
		start += 32;
	}
}

static int dump_mc7(int argc, char *argv[], int start_arg,
		    const char *iff_name)
{
	struct toetool_mem_range *op;
	unsigned int mem_id, addr, len;

	if (argc != start_arg + 3) return -1;

	if (!strcmp(argv[start_arg], "cm"))
		mem_id = MEM_CM;
	else if (!strcmp(argv[start_arg], "rx"))
		mem_id = MEM_PMRX;
	else if (!strcmp(argv[start_arg], "tx"))
		mem_id = MEM_PMTX;
	else
		errx(1, "unknown memory \"%s\"; must be one of \"cm\", \"tx\","
			" or \"rx\"", argv[start_arg]);

	if (get_int_arg(argv[start_arg + 1], &addr) ||
	    get_int_arg(argv[start_arg + 2], &len))
		return -1;

	op = malloc(sizeof(*op) + len);
	if (!op)
		err(1, "memory dump");

	op->cmd    = TOETOOL_GET_MEM;
	op->mem_id = mem_id;
	op->addr   = addr;
	op->len    = len;

	if (doit(iff_name, op) < 0)
		err(1, "memory dump");

	hexdump_8b(op->addr, (uint64_t *)op->buf, op->len / 8);
	free(op);
	return 0;
}

/* Max FW size is 32K including version, +4 bytes for the checksum. */
#define MAX_FW_IMAGE_SIZE (32768 + 4)

static int load_fw(int argc, char *argv[], int start_arg, const char *iff_name)
{
	int fd, len;
	struct toetool_mem_range *op;
	const char *fname = argv[start_arg];

	if (argc != start_arg + 1) return -1;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "load firmware");

	op = malloc(sizeof(*op) + MAX_FW_IMAGE_SIZE + 1);
	if (!op)
		err(1, "load firmware");

	len = read(fd, op->buf, MAX_FW_IMAGE_SIZE + 1);
	if (len < 0)
		err(1, "load firmware");
 	if (len > MAX_FW_IMAGE_SIZE)
		errx(1, "FW image too large");

	op->cmd = TOETOOL_LOAD_FW;
	op->len = len;

	if (doit(iff_name, op) < 0)
		err(1, "load firmware");
	return 0;
}

/* Max BOOT size is 255*512 bytes including the BIOS boot ROM basic header */
#define MAX_BOOT_IMAGE_SIZE (1024 * 512)

static int load_boot(int argc, char *argv[],
		     int start_arg, const char *iff_name)
{
	int fd, len;
	struct toetool_mem_range *op;
	const char *fname = argv[start_arg];

	if (argc != start_arg + 1) return -1;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "load boot image");

	op = malloc(sizeof(*op) + MAX_BOOT_IMAGE_SIZE + 1);
	if (!op)
		err(1, "load boot image");

	len = read(fd, op->buf, MAX_BOOT_IMAGE_SIZE + 1);
	if (len < 0)
		err(1, "load boot image");
 	if (len > MAX_BOOT_IMAGE_SIZE)
		errx(1, "boot image too large");

	op->cmd = TOETOOL_LOAD_BOOT;
	op->len = len;

	if (doit(iff_name, op) < 0)
		err(1, "load boot image");
	return 0;
}

static int clear_ofld_policy(const char *iff_name)
{
	struct toetool_mem_range op;

	op.cmd = TOETOOL_SET_OFLD_POLICY;
	op.len = 0;
	if (doit(iff_name, &op) < 0)
		err(1, "load offload policy");
	return 0;
}

static int load_ofld_policy(int argc, char *argv[], int start_arg,
			    const char *iff_name)
{
	int fd, len;
	struct stat st;
	struct toetool_mem_range *op;
	const char *fname = argv[start_arg];

	if (argc != start_arg + 1) return -1;

	if (!strcmp(fname, "none"))
		return clear_ofld_policy(iff_name);

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, fname);

	if (fstat(fd, &st) < 0)
		err(1, fname);

	op = malloc(sizeof(*op) + st.st_size);
	if (!op)
		err(1, "load offload policy");

	len = read(fd, op->buf, st.st_size);
	if (len < 0)
		err(1, fname);
 	if (len != st.st_size)
		errx(1, "could not read %s", fname);

	op->cmd = TOETOOL_SET_OFLD_POLICY;
	op->len = len;

	if (doit(iff_name, op) < 0)
		err(1, "load offload policy");
	return 0;
}

#if 0 /* Unsupported */
static int write_proto_sram(const char *fname, const char *iff_name)
{
	int i;
	char c;
	struct toetool_proto op = { .cmd = TOETOOL_SET_PROTO };
	uint32_t *p = op.data;
	FILE *fp = fopen(fname, "r");

	if (!fp)
		err(1, "load protocol sram");

	for (i = 0; i < 128; i++, p += 5) {
		int n = fscanf(fp, "%1x%8x%8x%8x%8x",
			       &p[0], &p[1], &p[2], &p[3], &p[4]);
		if (n != 5)
			errx(1, "%s: bad line %d", fname, i);
	}
	if (fscanf(fp, "%1s", &c) != EOF)
		errx(1, "%s: protocol sram image has too many lines", fname);
	fclose(fp);

	if (doit(iff_name, &op) < 0)
		err(1, "load protocol sram");
	return 0;
}
#endif

static int dump_proto_sram(const char *iff_name)
{
	int i, j;
	u8 buf[sizeof(struct ethtool_eeprom) + PROTO_SRAM_SIZE];
	struct ethtool_eeprom *ee = (struct ethtool_eeprom *)buf;
	u8 *p = buf + sizeof(struct ethtool_eeprom);

	ee->cmd = ETHTOOL_GEEPROM;
	ee->len = PROTO_SRAM_SIZE;
	ee->offset = PROTO_SRAM_EEPROM_ADDR;
	if (ethtool_call(iff_name, ee))
		err(1, "show protocol sram");

	for (i = 0; i < PROTO_SRAM_LINES; i++) {
		for (j = PROTO_SRAM_LINE_NIBBLES - 1; j >= 0; j--) {
			int nibble_idx = i * PROTO_SRAM_LINE_NIBBLES + j;
			u8 nibble = p[nibble_idx / 2];

			if (nibble_idx & 1)
				nibble >>= 4;
			else
				nibble &= 0xf;
			printf("%x", nibble);
		}
		putchar('\n');
	}
	return 0;
}

static int proto_sram_op(int argc, char *argv[], int start_arg,
			 const char *iff_name)
{
#if 0 /* Unsupported */
	if (argc == start_arg + 1)
		return write_proto_sram(argv[start_arg], iff_name);
#endif
	if (argc == start_arg)
		return dump_proto_sram(iff_name);
	return -1;
}

static int dump_qset_params(const char *iff_name)
{
	struct toetool_qset_params op;

	op.cmd = TOETOOL_GET_QSET_PARAMS;
	op.qset_idx = 0;

	while (doit(iff_name, &op) == 0) {
		if (!op.qset_idx)
			printf("%4s  %3s  %5s  %5s  %4s  %5s  %5s  %5s"
			       "  %4s  %4s  %-4s  %3s\n",
			       "QNUM", "IRQ", "TXQ0", "TXQ1", "TXQ2", "RSPQ",
			       "FL0", "FL1", "CONG", "LAT", "MODE", "LRO");
		if (op.qnum < 0 || op.qnum > 8)
			op.qnum = 0;
		if (op.vector < 0 || op.vector > 255)
			op.vector = 0;
		printf("%4u  %3u  %5u  %5u  %4u  %5u  %5u  %5u  %4u  %4u"
		       "  %-4s  %3u\n",
		       op.qnum + op.qset_idx,
		       op.vector,
		       op.txq_size[0], op.txq_size[1], op.txq_size[2],
		       op.rspq_size, op.fl_size[0], op.fl_size[1],
		       op.cong_thres, op.intr_lat,
		       op.polling ? "napi" : "irq",
		       op.lro);
		op.qset_idx++;
	}
	if (!op.qset_idx || (errno && errno != EINVAL))
		err(1, "get qset parameters");
	return 0;
}

static int qset_config(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	struct toetool_qset_params op;

	if (argc == start_arg)
		return dump_qset_params(iff_name);

	if (argc == 4)
		errx(1, "missing qset parameter \n"
			"allowed parameters are \"txq0\", \"txq1\", "
			"\"txq2\", \"rspq\", \"fl0\", \"fl1\", \"lat\", "
			"\"cong\", \"mode\' and \"lro\"");

	if (argc > 4)
		if (argc % 2)
			errx(1, "missing value for qset parameter \"%s\"",
				argv[argc - 1]);

	if (get_int_arg(argv[start_arg++], &op.qset_idx))
		return -1;

	op.txq_size[0] = op.txq_size[1] = op.txq_size[2] = -1;
	op.fl_size[0] = op.fl_size[1] = op.rspq_size = -1;
	op.polling = op.lro = op.intr_lat = op.cong_thres = -1;

	while (start_arg + 2 <= argc) {
		int32_t *param = NULL;

		if (!strcmp(argv[start_arg], "txq0"))
			param = &op.txq_size[0];
		else if (!strcmp(argv[start_arg], "txq1"))
			param = &op.txq_size[1];
		else if (!strcmp(argv[start_arg], "txq2"))
			param = &op.txq_size[2];
		else if (!strcmp(argv[start_arg], "rspq"))
			param = &op.rspq_size;
		else if (!strcmp(argv[start_arg], "fl0"))
			param = &op.fl_size[0];
		else if (!strcmp(argv[start_arg], "fl1"))
			param = &op.fl_size[1];
		else if (!strcmp(argv[start_arg], "lat"))
			param = &op.intr_lat;
		else if (!strcmp(argv[start_arg], "cong"))
			param = &op.cong_thres;
		else if (!strcmp(argv[start_arg], "mode"))
			param = &op.polling;
                else if (!strcmp(argv[start_arg], "lro"))
                        param = &op.lro;
		else
			errx(1, "unknown qset parameter \"%s\"\n"
			     "allowed parameters are \"txq0\", \"txq1\", "
			     "\"txq2\", \"rspq\", \"fl0\", \"fl1\", \"lat\", "
			     "\"cong\", \"mode\' and \"lro\"", argv[start_arg]);

		start_arg++;

		if (param == &op.polling) {
			if (!strcmp(argv[start_arg], "irq"))
				op.polling = 0;
			else if (!strcmp(argv[start_arg], "napi"))
				op.polling = 1;
			else
				errx(1, "illegal qset mode \"%s\"\n"
				     "known modes are \"irq\" and \"napi\"",
				     argv[start_arg]);
		} else if (get_int_arg(argv[start_arg], (uint32_t *)param))
			return -1;
		start_arg++;
	}
	if (start_arg != argc)
		errx(1, "unknown parameter %s", argv[start_arg]);

#if 0
	printf("%4u %6d %6d %6d %6d %6d %6d %5d %9d   %d\n", op.qset_idx,
	       op.txq_size[0], op.txq_size[1], op.txq_size[2],
	       op.rspq_size, op.fl_size[0], op.fl_size[1], op.cong_thres,
	       op.intr_lat, op.polling);
#endif
	op.cmd = TOETOOL_SET_QSET_PARAMS;
	if (doit(iff_name, &op) < 0)
		err(1, "set qset parameters");

	return 0;
}

static int qset_num_config(int argc, char *argv[], int start_arg,
			   const char *iff_name)
{
	struct toetool_reg op;

	if (argc == start_arg) {
		op.cmd = TOETOOL_GET_QSET_NUM;
		if (doit(iff_name, &op) < 0)
			err(1, "get qsets");
		printf("%u\n", op.val);
		return 0;
	}

	if (argc != start_arg + 1)
		return -1;
	if (get_int_arg(argv[start_arg], &op.val))
		return -1;

	op.cmd = TOETOOL_SET_QSET_NUM;
	if (doit(iff_name, &op) < 0)
		err(1, "set qsets");
	return 0;
}

/*
 * Parse a string containing an IP address with an optional network prefix.
 */
static int parse_ipaddr(const char *s, uint32_t *addr, uint32_t *mask)
{
	char *p, *slash;
	struct in_addr ia;

	*mask = 0xffffffffU;
	slash = strchr(s, '/');
	if (slash)
		*slash = 0;
	if (!inet_aton(s, &ia)) {
		if (slash)
			*slash = '/';
		*addr = 0;
		return -1;
	}
	*addr = ntohl(ia.s_addr);
	if (slash) {
		unsigned int prefix = strtoul(slash + 1, &p, 10);

		*slash = '/';
		if (p == slash + 1 || *p || prefix > 32)
			return -1;
		*mask <<= (32 - prefix);
	}
	return 0;
}

/*
 * Parse a string containing a value and an optional colon separated mask.
 */
static int parse_val_mask_param(const char *s, uint32_t *val, uint32_t *mask,
				uint32_t default_mask)
{
	char *p;

	*mask = default_mask;
	*val = strtoul(s, &p, 0);
	if (p == s || *val > default_mask)
		return -1;
	if (*p == ':' && p[1])
		*mask = strtoul(p + 1, &p, 0);
	return *p || *mask > default_mask ? -1 : 0;
}

static int parse_trace_param(const char *s, uint32_t *val, uint32_t *mask)
{
	return strchr(s, '.') ? parse_ipaddr(s, val, mask) :
				parse_val_mask_param(s, val, mask, 0xffffffffU);
}

static int trace_config(int argc, char *argv[], int start_arg,
			const char *iff_name)
{
	uint32_t val, mask;
	struct toetool_trace op;

	if (argc == start_arg)
		return -1;

	memset(&op, 0, sizeof(op));
	if (!strcmp(argv[start_arg], "tx"))
		op.config_tx = 1;
	else if (!strcmp(argv[start_arg], "rx"))
		op.config_rx = 1;
	else if (!strcmp(argv[start_arg], "all"))
		op.config_tx = op.config_rx = 1;
	else
		errx(1, "bad trace filter \"%s\"; must be one of \"rx\", "
		     "\"tx\" or \"all\"", argv[start_arg]);

	if (argc == ++start_arg) {
		op.cmd = TOETOOL_GET_TRACE_FILTER;
		if (doit(iff_name, &op) < 0)
			err(1, "trace");
		printf("sip: %x:%x, dip: %x:%x, sport: %x:%x, dport: %x:%x, "
	        "interface: %x:%x, vlan: %x:%x, proto: %x:%x, "
	        "invert: %u, tx_enable: %u, rx_enable: %u\n", op.sip,
	        op.sip_mask, op.dip, op.dip_mask, op.sport, op.sport_mask,
	        op.dport, op.dport_mask, op.intf, op.intf_mask, op.vlan,
	        op.vlan_mask, op.proto, op.proto_mask, op.invert_match,
	        op.trace_tx, op.trace_rx);
		return 0;
	}
	if (!strcmp(argv[start_arg], "on")) {
		op.trace_tx = op.config_tx;
		op.trace_rx = op.config_rx;
	} else if (strcmp(argv[start_arg], "off"))
		errx(1, "bad argument \"%s\"; must be \"on\" or \"off\"",
		     argv[start_arg]);

	start_arg++;
	if (start_arg < argc && !strcmp(argv[start_arg], "not")) {
		op.invert_match = 1;
		start_arg++;
	}

	while (start_arg + 2 <= argc) {
		int ret = parse_trace_param(argv[start_arg + 1], &val, &mask);

		if (!strcmp(argv[start_arg], "interface")) {
			op.intf = val;
			op.intf_mask = mask;
		} else if (!strcmp(argv[start_arg], "sip")) {
			op.sip = val;
			op.sip_mask = mask;
		} else if (!strcmp(argv[start_arg], "dip")) {
			op.dip = val;
			op.dip_mask = mask;
		} else if (!strcmp(argv[start_arg], "sport")) {
			op.sport = val;
			op.sport_mask = mask;
		} else if (!strcmp(argv[start_arg], "dport")) {
			op.dport = val;
			op.dport_mask = mask;
		} else if (!strcmp(argv[start_arg], "vlan")) {
			op.vlan = val;
			op.vlan_mask = mask;
		} else if (!strcmp(argv[start_arg], "proto")) {
			op.proto = val;
			op.proto_mask = mask;
		} else
			errx(1, "unknown trace parameter \"%s\"\n"
			     "known parameters are \"interface\", \"sip\", "
			     "\"dip\", \"sport\", \"dport\", \"vlan\", "
			     "\"proto\"", argv[start_arg]);
		if (ret < 0)
			errx(1, "bad parameter \"%s\"", argv[start_arg + 1]);
		start_arg += 2;
	}
	if (start_arg != argc)
		errx(1, "unknown parameter \"%s\"", argv[start_arg]);

#if 0
	printf("sip: %x:%x, dip: %x:%x, sport: %x:%x, dport: %x:%x, "
	       "interface: %x:%x, vlan: %x:%x, tx_config: %u, rx_config: %u, "
	       "invert: %u, tx_enable: %u, rx_enable: %u\n", op.sip,
	       op.sip_mask, op.dip, op.dip_mask, op.sport, op.sport_mask,
	       op.dport, op.dport_mask, op.intf, op.intf_mask, op.vlan,
	       op.vlan_mask, op.config_tx, op.config_rx, op.invert_match,
	       op.trace_tx, op.trace_rx);
#endif
	op.cmd = TOETOOL_SET_TRACE_FILTER;
	if (doit(iff_name, &op) < 0)
		err(1, "trace");
	return 0;
}

static int read_nqsets(const char *iff_name, int *sq, int *nq)
{
	struct toetool_qset_params op;

	op.cmd = TOETOOL_GET_QSET_PARAMS;
	op.qset_idx = 0;

	while (doit(iff_name, &op) == 0) {
		if (!op.qset_idx)
			*sq = op.qnum;
		op.qset_idx++;
	}

	*nq = op.qset_idx;

	return 0;
}


static int setup_lro(int argc, char *argv[], int start_arg,
		const char *iff_name)
{
	int sq, nq, lq;
        char sbuf0[0];

	if (argc == start_arg)
		errx(1, "missing argument to enable/disable lro");

	if (argc > 4)
		errx(1, "too many arguments");

	read_nqsets(iff_name, &sq, &nq);

	argv[4] = "lro";
	if (!strcmp(argv[3], "on") || !strcmp(argv[3], "1"))
		argv[5] = "1";
	else if (!strcmp(argv[3], "off") || !strcmp(argv[3], "0"))
		argv[5] = "0";
	else
		errx(1, "bad argument \"%s\"; must be \"on\" or \"off\"",
			argv[3]);

	lq = sq + nq;
	while (sq < lq) {
		sprintf(sbuf0, "%i", sq);
		argv[3] = sbuf0;
		qset_config(6, argv, 3, iff_name);
		sq++;
	}

	printf("%s LRO for all Queues on %s\n",
		!strcmp(argv[5], "1") ? "Enabled" : "Disabled", iff_name);

	return 0;
}

static int setup_napi(int argc, char *argv[], int start_arg,
		const char *iff_name)
{
	int sq, nq, lq;
        char sbuf0[0];

	if (argc == start_arg)
		errx(1, "missing argument to enable/disable napi");

	if (argc > 4)
		errx(1, "too many arguments");

	read_nqsets(iff_name, &sq, &nq);

	argv[4] = "mode";
	if (!strcmp(argv[3], "on") || !strcmp(argv[3], "1"))
		argv[5] = "napi";
	else if (!strcmp(argv[3], "off") || !strcmp(argv[3], "0"))
		argv[5] = "irq";
	else
		errx(1, "bad argument \"%s\"; must be \"on\" or \"off\"",
			argv[3]);

	lq = sq + nq;
	while (sq < lq) {
		sprintf(sbuf0, "%i", sq);
		argv[3] = sbuf0;
		qset_config(6, argv, 3, iff_name);
		sq++;
	}

	printf("%s NAPI for all Queues on %s\n",
		!strcmp(argv[5], "napi") ? "Enabled" : "Disabled", iff_name);

	return 0;
}

static int filter_config(int argc, char *argv[], int start_arg,
			 const char *iff_name)
{
	int ret = 0;
	uint32_t val, mask;
	struct ch_filter op;

	if (argc < start_arg + 1)
		return -1;

	memset(&op, 0, sizeof(op));
	op.mac_addr_idx = 0xffff;
	op.rss = 1;

	if (get_int_arg(argv[start_arg++], &op.filter_id))
		return -1;
	if (argc == start_arg + 1 && (!strcmp(argv[start_arg], "delete") ||
				      !strcmp(argv[start_arg], "clear"))) {
		op.cmd = TOETOOL_DEL_FILTER;
		if (doit(iff_name, &op) < 0) {
			if (errno == EBUSY)
				err(1, "no filter support when offload in use");
			err(1, "delete filter");
		}
		return 0;
	}

	while (start_arg + 2 <= argc) {
		if (!strcmp(argv[start_arg], "sip")) {
			ret = parse_ipaddr(argv[start_arg + 1], &op.val.sip,
					   &op.mask.sip);
		} else if (!strcmp(argv[start_arg], "dip")) {
			ret = parse_ipaddr(argv[start_arg + 1], &op.val.dip,
					   &op.mask.dip);
		} else if (!strcmp(argv[start_arg], "sport")) {
			ret = parse_val_mask_param(argv[start_arg + 1],
						   &val, &mask, 0xffff);
			op.val.sport = val;
			op.mask.sport = mask;
		} else if (!strcmp(argv[start_arg], "dport")) {
			ret = parse_val_mask_param(argv[start_arg + 1],
						   &val, &mask, 0xffff);
			op.val.dport = val;
			op.mask.dport = mask;
		} else if (!strcmp(argv[start_arg], "vlan")) {
			ret = parse_val_mask_param(argv[start_arg + 1],
						   &val, &mask, 0xfff);
			op.val.vlan = val;
			op.mask.vlan = mask;
		} else if (!strcmp(argv[start_arg], "prio")) {
			ret = parse_val_mask_param(argv[start_arg + 1],
						   &val, &mask, 7);
			op.val.vlan_prio = val;
			op.mask.vlan_prio = mask;
		} else if (!strcmp(argv[start_arg], "mac")) {
			if (!strcmp(argv[start_arg + 1], "none"))
				val = -1;
			else
				ret = get_int_arg(argv[start_arg + 1], &val);
			op.mac_hit = val != -1;
			op.mac_addr_idx = op.mac_hit ? val : 0;
		} else if (!strcmp(argv[start_arg], "type")) {
			if (!strcmp(argv[start_arg + 1], "tcp"))
				op.proto = 1;
			else if (!strcmp(argv[start_arg + 1], "udp"))
				op.proto = 2;
			else if (!strcmp(argv[start_arg + 1], "frag"))
				op.proto = 3;
			else
				errx(1, "unknown type \"%s\"; must be one of "
				     "\"tcp\", \"udp\", or \"frag\"",
				     argv[start_arg + 1]);
		} else if (!strcmp(argv[start_arg], "queue")) {
			ret = get_int_arg(argv[start_arg + 1], &val);
			op.qset = val;
			op.rss = 0;
		} else if (!strcmp(argv[start_arg], "action")) {
			if (!strcmp(argv[start_arg + 1], "pass"))
				op.pass = 1;
			else if (strcmp(argv[start_arg + 1], "drop"))
				errx(1, "unknown action \"%s\"; must be one of "
				     "\"pass\" or \"drop\"",
				     argv[start_arg + 1]);
		} else
 			errx(1, "unknown filter parameter \"%s\"\n"
			     "known parameters are \"mac\", \"sip\", "
			     "\"dip\", \"sport\", \"dport\", \"vlan\", "
			     "\"prio\", \"type\", \"queue\", and \"action\"",
			     argv[start_arg]);
		if (ret < 0)
			errx(1, "bad value \"%s\" for parameter \"%s\"",
			     argv[start_arg + 1], argv[start_arg]);
		start_arg += 2;
	}
	if (start_arg != argc)
		errx(1, "no value for \"%s\"", argv[start_arg]);
#if 0
	printf("sip: %x:%x, dip: %x:%x, sport: %u:%x, dport: %u:%x, "
	       "vlan: %u:%x, prio: %u:%x, mac: %u, mac_hit: %u, type: %u, "
	       "want_filter_id: %u, pass: %u, "
	       "rss: %u, queue: %u\n", op.val.sip,
	       op.mask.sip, op.val.dip, op.mask.dip, op.val.sport,
	       op.mask.sport, op.val.dport, op.mask.dport,
	       op.val.vlan, op.mask.vlan, op.val.vlan_prio, op.mask.vlan_prio,
	       op.mac_addr_idx, op.mac_hit, op.proto, op.want_filter_id,
	       op.pass, op.rss, op.qset);
#endif

	op.cmd = TOETOOL_SET_FILTER;
	if (doit(iff_name, &op) < 0) {
		if (errno == EBUSY)
			err(1, "no filter support when offload in use");
		err(1, "set filter");
	}
	
	return 0;
}

static int get_sched_param(int argc, char *argv[], int pos, unsigned int *valp)
{
	if (pos + 1 >= argc)
		errx(1, "missing value for %s", argv[pos]);
	if (get_int_arg(argv[pos + 1], valp))
		exit(1);
	return 0;
}

static int tx_sched(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_hw_sched op;
	unsigned int idx, val;

	if (argc < 5 || get_int_arg(argv[start_arg++], &idx))
		return -1;

	op.cmd = TOETOOL_SET_HW_SCHED;
	op.sched = idx;
	op.mode = op.channel = -1;
	op.kbps = op.class_ipg = op.flow_ipg = -1;

	while (argc > start_arg) {
		if (!strcmp(argv[start_arg], "mode")) {
			if (start_arg + 1 >= argc)
				errx(1, "missing value for mode");
			if (!strcmp(argv[start_arg + 1], "class"))
				op.mode = 0;
			else if (!strcmp(argv[start_arg + 1], "flow"))
				op.mode = 1;
			else
				errx(1, "bad mode \"%s\"", argv[start_arg + 1]);
		} else if (!strcmp(argv[start_arg], "channel") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.channel = val;
		else if (!strcmp(argv[start_arg], "rate") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.kbps = val;
		else if (!strcmp(argv[start_arg], "ipg") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.class_ipg = val;
		else if (!strcmp(argv[start_arg], "flowipg") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.flow_ipg = val;
		else
			errx(1, "unknown scheduler parameter \"%s\"",
			     argv[start_arg]);
		start_arg += 2;
	}

	if (doit(iff_name, &op) < 0)
		 err(1, "pktsched");

	return 0;
}

static int pktsched(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct toetool_pktsched_params op;
	unsigned int idx, min = -1, max;

	if (argc < 4)
		errx(1, "no scheduler specified");

	if (!strcmp(argv[start_arg], "port")) {
		if (argc <= start_arg + 1)
			return -1;

		op.sched = PKTSCHED_PORT;

		/* no min and max provided, do a get */
		if (argc == start_arg + 2) {
			op.cmd = TOETOOL_GET_PKTSCHED;
			if (get_int_arg(argv[start_arg + 1], &idx))
				return -1;
			goto doit;
		}

		if (argc != start_arg + 4)
			return -1;

		if (get_int_arg(argv[start_arg + 1], &idx) ||
		    get_int_arg(argv[start_arg + 2], &min) ||
		    get_int_arg(argv[start_arg + 3], &max))
			return -1;

		if (min > max)
			errx(-1, "error min value (%d) is greater"
			     "than max value (%d)", min, max);
		if (min < 0 || max < 0 || min > 100 || max > 100)
			errx(-1, "error min and max values should be"
			     " between 0 and 100");

	} else if (!strcmp(argv[start_arg], "tunnelq")) {
		if (argc <= start_arg + 1)
			return -1;

		op.sched = PKTSCHED_TUNNELQ;

		/* no max value provided, do a get */
		if (argc == start_arg + 2) {
			op.cmd = TOETOOL_GET_PKTSCHED;
			get_int_arg(argv[start_arg + 1], &idx);
			goto doit;
		}

		if (argc != start_arg + 3)
			return -1;

		if (get_int_arg(argv[start_arg + 1], &idx) ||
		    get_int_arg(argv[start_arg + 2], &max))
			return -1;

		if (max > 100 || max < 0)
			errx(-1, "error max value should be between 0 and 100");

	} else if (!strcmp(argv[start_arg], "tx"))
		return tx_sched(argc, argv, start_arg + 1, iff_name);
	else
		errx(1, "unknown scheduler \"%s\"; must be one of \"port\", " 
			"\"tunnelq\" or \"tx\"", argv[start_arg]);
 
	op.min = min;
	op.max = max;
	op.binding = -1;
	op.cmd = TOETOOL_SET_PKTSCHED;
doit:	op.idx = idx;
	if (doit(iff_name, &op) < 0)
		 err(1, "pktsched");

	if (op.cmd == TOETOOL_GET_PKTSCHED) {
		if (op.sched == PKTSCHED_PORT)
			printf("Port Min %d \tPort Max %d\n", op.min, op.max);
		else if (op.sched == PKTSCHED_TUNNELQ)
			printf("Tunnelq Max %d\n", op.max);
	}

	return 0;
}

static int clear_stats(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	struct toetool_reg op;

	op.cmd = TOETOOL_CLEAR_STATS;
	op.addr = -1;

	if (argc == start_arg)
		op.val = STATS_PORT | STATS_QUEUE;
	else if (argc == start_arg + 1) {
		if (!strcmp(argv[start_arg], "port"))
			op.val = STATS_PORT;
		else if (!strcmp(argv[start_arg], "queue"))
			op.val = STATS_QUEUE;
		else
			return -1;
	} else if (argc == start_arg + 2 && !strcmp(argv[start_arg], "queue")) {
		if (get_int_arg(argv[start_arg + 1], &op.addr))
			return -1;
		op.val = STATS_QUEUE;
	} else
		return -1;

	if (doit(iff_name, &op) < 0)
		 err(1, "clearstats");
	return 0;
}

static int get_up_la(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct toetool_la op;
	int i, idx, max_idx, entries;

	op.cmd = TOETOOL_GET_UP_LA;
	op.bufsize = sizeof(op.la);
	op.idx = -1;

	if (doit(iff_name, &op) < 0)
		 err(1, "up_la");

	if (op.stopped)
		printf("LA is not running\n");

	entries = op.bufsize / 4;
	idx = (int)op.idx;
	max_idx = (entries / 4) - 1;
	for (i = 0; i < max_idx; i++) {
		printf("%04x %08x %08x\n",
		       op.la[idx], op.la[idx+2], op.la[idx+1]);
		idx = (idx + 4) & (entries - 1);
	}

	return 0;
}

static int get_up_ioqs(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct toetool_ioqs op;
	int i, entries;

	op.cmd = TOETOOL_GET_UP_IOQS;
	op.bufsize = sizeof(op.ioqs);

	if (doit(iff_name, &op) < 0)
		 err(1, "up_ioqs");

	printf("ioq_rx_enable   : 0x%08x\n", op.ioq_rx_enable);
	printf("ioq_tx_enable   : 0x%08x\n", op.ioq_tx_enable);
	printf("ioq_rx_status   : 0x%08x\n", op.ioq_rx_status);
	printf("ioq_tx_status   : 0x%08x\n", op.ioq_tx_status);
	
	entries = op.bufsize / sizeof(struct ioq_entry);
	for (i = 0; i < entries; i++) {
		printf("\nioq[%d].cp       : 0x%08x\n", i,
		       op.ioqs[i].ioq_cp);
		printf("ioq[%d].pp       : 0x%08x\n", i,
		       op.ioqs[i].ioq_pp);
		printf("ioq[%d].alen     : 0x%08x\n", i,
		       op.ioqs[i].ioq_alen);
		printf("ioq[%d].stats    : 0x%08x\n", i,
		       op.ioqs[i].ioq_stats);
		printf("  sop %u\n", op.ioqs[i].ioq_stats >> 16);
		printf("  eop %u\n", op.ioqs[i].ioq_stats  & 0xFFFF);
	}

	return 0;
}

static int
run_cmd(int argc, char *argv[], const char *iff_name)
{
	int r = -1;
	if (!strcmp(argv[2], "reg"))
		r = register_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "mdio"))
		r = mdio_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "up"))
		r = device_up(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "mtus"))
		r = mtu_tab_op(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "pm"))
		r = conf_pm(argc, argv, 3, iff_name);
#ifdef WRC
	else if (!strcmp(argv[2], "wrc"))
		r = get_wrc(argc, argv, 3, iff_name);
#endif
	else if (!strcmp(argv[2], "regdump"))
		r = dump_regs(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "tcamdump"))
		r = dump_tcam(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "memdump"))
		r = dump_mc7(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "meminfo"))
		r = meminfo(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "context"))
		r = get_sge_context(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "desc"))
		r = get_sge_desc(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadfw"))
		r = load_fw(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadboot"))
		r = load_boot(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "policy"))
		r = load_ofld_policy(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "proto"))
		r = proto_sram_op(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qset"))
		r = qset_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qsets"))
		r = qset_num_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "trace"))
		r = trace_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "pktsched"))
		r = pktsched(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "napi"))
		r = setup_napi(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "lro"))
		r = setup_lro(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "tcb"))
		r = get_tcb2(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "filter"))
		r = filter_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "clearstats"))
		r = clear_stats(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "la"))
		r = get_up_la(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "ioqs"))
		r = get_up_ioqs(argc, argv, 3, iff_name);
#if 0 /* Unsupported */
	else if (!strcmp(argv[2], "tpi"))
		r = tpi_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "tcam"))
		r = conf_tcam(argc, argv, 3, iff_name);
#endif

	if (r == -1)
		usage(stderr);
	return 0;
}

static int
run_cmd_loop(int argc, char *argv[], const char *iff_name)
{
	int n, i;
	char buf[64];
	char *args[8], *s;

	args[0] = argv[0];
	args[1] = argv[1];

	/*
	 * Fairly simplistic loop.  Displays a "> " prompt and processes any
	 * input as a cxgbtool command.  You're supposed to enter only the part
	 * after "cxgbtool cxgbX".  Use "quit" or "exit" to exit.  Any error in
	 * the command will also terminate cxgbtool.
	 */
	do {
		fprintf(stdout, "> ");
		fflush(stdout);
		n = read(STDIN_FILENO, buf, sizeof(buf));
		if (n > sizeof(buf) - 1) {
			fprintf(stdout, "too much input.\n");
			return (0);
		} else if (n <= 0)
			return (0);

		if (buf[--n] != '\n')
			continue;
		else
			buf[n] = 0;

		s = &buf[0];
		for (i = 2; i < sizeof(args)/sizeof(args[0]) - 1; i++) {
			while (s && (*s == ' ' || *s == '\t'))
				s++;
			if ((args[i] = strsep(&s, " \t")) == NULL)
				break;
		}
		args[sizeof(args)/sizeof(args[0]) - 1] = 0;

		if (!strcmp(args[2], "quit") || !strcmp(args[2], "exit"))
			return (0);

		(void) run_cmd(i, args, iff_name);
	} while (1);

	/* Can't really get here */
	return (0);
}

int
main(int argc, char *argv[])
{
	int r = -1;
	const char *iff_name;

	progname = argv[0];

	if (argc == 2) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
			usage(stdout);
		if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
			printf("%s version %s\n", PROGNAME, VERSION);
			printf("%s\n", COPYRIGHT);
			exit(0);
		}
	}

	if (argc < 3) usage(stderr);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		err(1, "Cannot get control socket");

	iff_name = argv[1];

	if (argc == 3 && !strcmp(argv[2], "stdio"))
		r = run_cmd_loop(argc, argv, iff_name);
	else
		r = run_cmd(argc, argv, iff_name);

	return (r);
}
