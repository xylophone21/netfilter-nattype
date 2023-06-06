#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>

#ifndef NF_NAT_RANGE_PROTO_RANDOM_FULLY
#define NF_NAT_RANGE_PROTO_RANDOM_FULLY (1 << 4)
#endif

enum {
	O_TO_PORTS = 0,
	O_RANDOM,
	O_RANDOM_FULLY,
	O_TO_SRC,
	O_NAT_TYPE,
};

enum {
	NAT_TYPE_FULL_CONE,
	NAT_TYPE_Address_Restricted,
	NAT_TYPE_Port_Restricted,
};

struct nf_nat_ipv4_multi_range_compat_withtype {
	unsigned int			rangesize;
	struct nf_nat_ipv4_range	range[1];
	int nattype;
};

// type ./iptables -t nat -j FULLCONENAT -h to see this help
static void FULLCONENAT_help(void)
{
	printf(
"FULLCONENAT target options:\n"
" --to-source [<ipaddr>[-<ipaddr>]]\n"
"				Address to map source to.\n"
" --to-ports <port>[-<port>]\n"
"				Port (range) to map to.\n"
" --nat-type <type>\n"
"				Set nat type, fc:Full Cone, ar:Address-Restricted Cone, pr:Port-Restricted Cone NAT;\n"
" --random\n"
"				Randomize source port.\n"
" --random-fully\n"
"				Fully randomize source port.\n");
}

static const struct xt_option_entry FULLCONENAT_opts[] = {
	{.name = "to-ports", .id = O_TO_PORTS, .type = XTTYPE_STRING},
	{.name = "random", .id = O_RANDOM, .type = XTTYPE_NONE},
	{.name = "random-fully", .id = O_RANDOM_FULLY, .type = XTTYPE_NONE},
	{.name = "to-source", .id = O_TO_SRC, .type = XTTYPE_STRING},
	{.name = "nat-type", .id = O_NAT_TYPE, .type = XTTYPE_STRING},
	XTOPT_TABLEEND,
};

static void parse_nat_type(const char *orig_arg, struct nf_nat_ipv4_multi_range_compat_withtype *mr)
{
	if (strcmp(orig_arg,"fc") == 0) {
		mr->nattype = NAT_TYPE_FULL_CONE;
	} else if(strcmp(orig_arg,"ar") == 0) {
		mr->nattype = NAT_TYPE_Address_Restricted;
	} else if(strcmp(orig_arg,"pr") == 0) {
		mr->nattype = NAT_TYPE_Port_Restricted;
	} else {
		xtables_error(PARAMETER_PROBLEM, "Bad nat-type \"%s\"\n",
			   orig_arg);
	}
}

static void parse_to(const char *orig_arg, struct nf_nat_ipv4_multi_range_compat_withtype *mr)
{
	char *arg, *dash;
	const struct in_addr *ip;

	arg = strdup(orig_arg);
	if (arg == NULL)
		xtables_error(RESOURCE_PROBLEM, "strdup");

	mr->range[0].flags |= NF_NAT_RANGE_MAP_IPS;
	dash = strchr(arg, '-');

	if (dash)
		*dash = '\0';

	ip = xtables_numeric_to_ipaddr(arg);
	if (!ip)
		xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
			   arg);
	mr->range[0].min_ip = ip->s_addr;
	if (dash) {
		ip = xtables_numeric_to_ipaddr(dash+1);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
				   dash+1);
		mr->range[0].max_ip = ip->s_addr;
	} else
		mr->range[0].max_ip = mr->range[0].min_ip;

	free(arg);
}

static void FULLCONENAT_init(struct xt_entry_target *t)
{
	struct nf_nat_ipv4_multi_range_compat_withtype *mr = (struct nf_nat_ipv4_multi_range_compat_withtype *)t->data;

	/* Actually, it's 0, but it's ignored at the moment. */
	mr->rangesize = 1;
}

/* Parses ports */
static void
parse_ports(const char *arg, struct nf_nat_ipv4_multi_range_compat_withtype *mr)
{
	char *end;
	unsigned int port, maxport;

	mr->range[0].flags |= NF_NAT_RANGE_PROTO_SPECIFIED;

	if (!xtables_strtoui(arg, &end, &port, 0, UINT16_MAX))
		xtables_param_act(XTF_BAD_VALUE, "FULLCONENAT", "--to-ports", arg);

	switch (*end) {
	case '\0':
		mr->range[0].min.tcp.port
			= mr->range[0].max.tcp.port
			= htons(port);
		return;
	case '-':
		if (!xtables_strtoui(end + 1, NULL, &maxport, 0, UINT16_MAX))
			break;

		if (maxport < port)
			break;

		mr->range[0].min.tcp.port = htons(port);
		mr->range[0].max.tcp.port = htons(maxport);
		return;
	default:
		break;
	}
	xtables_param_act(XTF_BAD_VALUE, "FULLCONENAT", "--to-ports", arg);
}

static void FULLCONENAT_parse(struct xt_option_call *cb)
{
	const struct ipt_entry *entry = cb->xt_entry;
	int portok;
	struct nf_nat_ipv4_multi_range_compat_withtype *mr = cb->data;

	if (entry->ip.proto == IPPROTO_TCP
	    || entry->ip.proto == IPPROTO_UDP
	    || entry->ip.proto == IPPROTO_SCTP
	    || entry->ip.proto == IPPROTO_DCCP
	    || entry->ip.proto == IPPROTO_ICMP)
		portok = 1;
	else
		portok = 0;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_PORTS:
		if (!portok)
			xtables_error(PARAMETER_PROBLEM,
				   "Need TCP, UDP, SCTP or DCCP with port specification");
		parse_ports(cb->arg, mr);
		break;
	case O_TO_SRC:
		parse_to(cb->arg, mr);
		break;
	case O_NAT_TYPE:
		parse_nat_type(cb->arg, mr);
		break;
	case O_RANDOM:
		mr->range[0].flags |=  NF_NAT_RANGE_PROTO_RANDOM;
		break;
	case O_RANDOM_FULLY:
		mr->range[0].flags |=  NF_NAT_RANGE_PROTO_RANDOM_FULLY;
		break;
	}
}

// sudo ./iptables -t nat -L -n -v查看
static void
FULLCONENAT_print(const void *ip, const struct xt_entry_target *target,
                 int numeric)
{
	const struct nf_nat_ipv4_multi_range_compat_withtype *mr = (const void *)target->data;
	const struct nf_nat_ipv4_range *r = &mr->range[0];

	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		printf(" to:%s", xtables_ipaddr_to_numeric(&a));
		if (r->max_ip != r->min_ip) {
			a.s_addr = r->max_ip;
			printf("-%s", xtables_ipaddr_to_numeric(&a));
		}
	}

	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(" masq ports: ");
		printf("%hu", ntohs(r->min.tcp.port));
		if (r->max.tcp.port != r->min.tcp.port)
			printf("-%hu", ntohs(r->max.tcp.port));
	}

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" random");

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
		printf(" random-fully");

	switch(mr->nattype) {
		case NAT_TYPE_FULL_CONE:
			printf(" full-cone");
			break;
		case NAT_TYPE_Address_Restricted:
			printf(" address-restricted");
			break;
		case NAT_TYPE_Port_Restricted:
			printf(" port-restricted");
			break;
	}
}

// sudo ./iptables-save显示
static void
FULLCONENAT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct nf_nat_ipv4_multi_range_compat_withtype *mr = (const void *)target->data;
	const struct nf_nat_ipv4_range *r = &mr->range[0];

	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		struct in_addr a;

		a.s_addr = r->min_ip;
		printf(" --to-source %s", xtables_ipaddr_to_numeric(&a));
		if (r->max_ip != r->min_ip) {
			a.s_addr = r->max_ip;
			printf("-%s", xtables_ipaddr_to_numeric(&a));
		}
	}

	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(" --to-ports %hu", ntohs(r->min.tcp.port));
		if (r->max.tcp.port != r->min.tcp.port)
			printf("-%hu", ntohs(r->max.tcp.port));
	}

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" --random");

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
		printf(" --random-fully");

	switch(mr->nattype) {
		case NAT_TYPE_FULL_CONE:
			printf(" full-cone");
			break;
		case NAT_TYPE_Address_Restricted:
			printf(" address-restricted");
			break;
		case NAT_TYPE_Port_Restricted:
			printf(" port-restricted");
			break;
	}
}

static struct xtables_target fullconenat_tg_reg = {
	.name		= "FULLCONENAT",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat_withtype)),
	.userspacesize	= XT_ALIGN(sizeof(struct nf_nat_ipv4_multi_range_compat_withtype)),
	.help		= FULLCONENAT_help,
	.init		= FULLCONENAT_init,
	.x6_parse	= FULLCONENAT_parse,
	.print		= FULLCONENAT_print,
	.save		= FULLCONENAT_save,
	.x6_options	= FULLCONENAT_opts,
};

void _init(void)
{
	xtables_register_target(&fullconenat_tg_reg);
}
