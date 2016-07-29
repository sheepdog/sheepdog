#include <check.h>
#include <math.h>

#include "md.c"

/* Constant values for the chi-squared test */
#define DATA_SIZE 1024
#define DF 9 /* a degree of freedom */
#define CV 16.919 /* a critical value (p=0.05, df=9) */
#define EXP ((double)DATA_SIZE / (DF + 1)) /* an expected value */

/* uniform distribution */
const double uniform_dist[DF + 1] = {
	0,
	(double)UINT64_MAX / 10,
	(double)UINT64_MAX / 10 * 2,
	(double)UINT64_MAX / 10 * 3,
	(double)UINT64_MAX / 10 * 4,
	(double)UINT64_MAX / 10 * 5,
	(double)UINT64_MAX / 10 * 6,
	(double)UINT64_MAX / 10 * 7,
	(double)UINT64_MAX / 10 * 8,
	(double)UINT64_MAX / 10 * 9,
};

/* chi-squared distribution with 9 degrees of freedom */
const double chi2_dist[DF + 1] = {
	0.000,	4.168,	5.380,	6.393,	7.357,
	8.343,	9.414,	10.656,	12.242,	14.684,
};


/* return true if s2 is subset of s1 */
#define is_subset(s1, nr_s1, s2, nr_s2, cmp)			\
({								\
	bool ____ret = true;					\
	for (int __i = 0; __i < nr_s2; __i++) {			\
		if (!xbsearch((s2) + __i, s1, nr_s1, cmp)) {	\
			____ret = false;			\
			break;					\
		}						\
	}							\
	____ret;						\
})

/* calculate a chi-squared value */
static double get_chi2(const double *data, const double *dist)
{
	double chi2 = 0.0;
	int counts[DF + 1] = {};

	for (int i = 0; i < DATA_SIZE; i++) {
		for (int j = DF; j >= 0; j--) {
			if (dist[j] <= data[i]) {
				counts[j]++;
				break;
			}
		}
	}

	for (int i = 0; i < ARRAY_SIZE(counts); i++)
		chi2 += pow((double)counts[i] - EXP, 2) / EXP;

	return chi2;
}

/* do a chi-squared test */
static void chi2_test(void (*gen_data)(double *data, int idx))
{
	double sample_data[DATA_SIZE], chi2_data[DATA_SIZE], chi2;

	for (int i = 0; i < ARRAY_SIZE(chi2_data); i++) {
		gen_data(sample_data, i);
		chi2_data[i] = get_chi2(sample_data, uniform_dist);
	}

	chi2 = get_chi2(chi2_data, chi2_dist);

	ck_assert_msg(chi2 < CV, "chi-square test failed (chi-square: %lf,"
		      " critical value: %lf)", chi2, CV);
}

static void (*gen_basic_data)(double *data, int idx);

/* generate sample data with sd_hash() */
static void gen_sd_hash_data(double *data, int idx)
{
	static int n;

	for (int i = 0; i < DATA_SIZE; i++) {
		data[i] = sd_hash(&n, sizeof(n));
		n++;
	}
}

static void basic1_setup(void)
{
	gen_basic_data = gen_sd_hash_data;
}

/* generate sample data with sd_hash_next() */
static void gen_sd_hash_next_data(double *data, int idx)
{
	uint64_t hval = sd_hash(&idx, sizeof(idx));

	for (int i = 0; i < DATA_SIZE; i++) {
		hval = sd_hash_next(hval);
		data[i] = hval;
	}
}

static void basic2_setup(void)
{
	gen_basic_data = gen_sd_hash_next_data;
}

START_TEST(test_basic_dispersion)
{
	chi2_test(gen_basic_data);
}
END_TEST

static size_t (*gen_nodes)(struct sd_node *nodes, int idx);

/* generate one disk which has many virtual disks */
static size_t gen_many_vnodes(struct sd_node *nodes, int idx)
{
	memset(nodes, 0, sizeof(*nodes));

	/* IPv4 10.0.0.1 */
	nodes[0].nid.addr[12] = 10;
	nodes[0].nid.addr[15] = 1;
	nodes[0].nid.port = 7000 + idx;

	nodes[0].nr_vnodes = DATA_SIZE;

	return 1;
}

static void node1_setup(void)
{
	gen_nodes = gen_many_vnodes;
}

/* generate many daemons with one vnode on the same node */
static size_t gen_many_daemons_one_vnode(struct sd_node *nodes, int idx)
{
	memset(nodes, 0, sizeof(*nodes) * DATA_SIZE);

	for (int i = 0; i < DATA_SIZE; i++) {
		/* IPv4 10.0.x.y */
		nodes[i].nid.addr[12] = 10;
		nodes[i].nid.addr[14] = idx / 256;
		nodes[i].nid.addr[15] = idx % 256;
		nodes[i].nid.port = 7000 + i;
		nodes[i].nr_vnodes = 1;
	}

	return DATA_SIZE;
}

static void node2_setup(void)
{
	gen_nodes = gen_many_daemons_one_vnode;
}

/* generate many daemons with some vnodes on the same node */
static size_t gen_many_daemons_some_vnodes(struct sd_node *nodes, int idx)
{
	memset(nodes, 0, sizeof(*nodes) * DATA_SIZE);

	for (int i = 0; i < DATA_SIZE / 4; i++) {
		/* IPv4 10.0.x.y */
		nodes[i].nid.addr[12] = 10;
		nodes[i].nid.addr[14] = idx / 256;
		nodes[i].nid.addr[15] = idx % 256;
		nodes[i].nid.port = 7000 + i;
		nodes[i].nr_vnodes = 4;
	}

	return DATA_SIZE / 4;
}

static void node3_setup(void)
{
	gen_nodes = gen_many_daemons_some_vnodes;
}

/* generate many nodes who have only one virtual node */
static size_t gen_many_nodes_one_vnode(struct sd_node *nodes, int idx)
{
	memset(nodes, 0, sizeof(*nodes) * DATA_SIZE);

	for (int i = 0; i < DATA_SIZE; i++) {
		/* IPv4 10.0.x.y */
		nodes[i].nid.addr[12] = 10;
		nodes[i].nid.addr[14] = i / 256;
		nodes[i].nid.addr[15] = i % 256;
		nodes[i].nid.port = 7000 + idx;
		nodes[i].nr_vnodes = 1;
	}

	return DATA_SIZE;
}

static void node4_setup(void)
{
	gen_nodes = gen_many_nodes_one_vnode;
}

/* generate many nodes who have some virtual nodes */
static size_t gen_many_nodes_some_vnodes(struct sd_node *nodes, int idx)
{
	memset(nodes, 0, sizeof(*nodes) * DATA_SIZE);

	for (int i = 0; i < DATA_SIZE / 4; i++) {
		/* IPv4 10.0.x.y */
		nodes[i].nid.addr[12] = 10;
		nodes[i].nid.addr[14] = 0;
		nodes[i].nid.addr[15] = i;
		nodes[i].nid.port = 7000 + idx;
		nodes[i].nr_vnodes = 4;
	}

	return DATA_SIZE / 4;
}

static void node5_setup(void)
{
	gen_nodes = gen_many_nodes_some_vnodes;
}

static size_t get_vnodes_array(struct rb_root *vroot, struct sd_vnode *vnodes)
{
	struct sd_vnode *vnode;
	size_t nr = 0;

	rb_for_each_entry(vnode, vroot, rb) {
		nr++;
		*vnodes++ = *vnode;
	}

	return nr;
}

/* check the existing vnodes don't change */
START_TEST(test_nodes_update)
{
	size_t nr_vnodes;
	size_t nr_vnodes_after;
	struct sd_node nodes[DATA_SIZE];
	struct sd_vnode vnodes[DATA_SIZE];
	struct sd_vnode vnodes_after[DATA_SIZE];
	struct rb_root vroot;

	gen_nodes(nodes, 0);

	INIT_RB_ROOT(&vroot);
	node_to_vnodes(nodes, &vroot);
	nr_vnodes = get_vnodes_array(&vroot, vnodes);
	/* 1 node join */
	node_to_vnodes(nodes + 1, &vroot);
	nr_vnodes_after = get_vnodes_array(&vroot, vnodes_after);
	ck_assert(is_subset(vnodes_after, nr_vnodes_after, vnodes,
			    nr_vnodes, vnode_cmp));

	INIT_RB_ROOT(&vroot);
	for (int i = 0; i < 100; i++)
		node_to_vnodes(nodes + i, &vroot);
	nr_vnodes = get_vnodes_array(&vroot, vnodes);
	/* 1 node join */
	node_to_vnodes(nodes + 100, &vroot);
	nr_vnodes_after = get_vnodes_array(&vroot, vnodes_after);
	ck_assert(is_subset(vnodes_after, nr_vnodes_after, vnodes,
			    nr_vnodes, vnode_cmp));
	/* 100 nodes join */
	for (int i = 101; i < 200; i++)
		node_to_vnodes(nodes + i, &vroot);
	nr_vnodes_after = get_vnodes_array(&vroot, vnodes_after);
	ck_assert(is_subset(vnodes_after, nr_vnodes_after, vnodes,
			    nr_vnodes, vnode_cmp));

	INIT_RB_ROOT(&vroot);
	node_to_vnodes(nodes, &vroot);
	node_to_vnodes(nodes + 1, &vroot);
	nr_vnodes = get_vnodes_array(&vroot, vnodes);
	/* 1 node leave */
	INIT_RB_ROOT(&vroot);
	node_to_vnodes(nodes, &vroot);
	nr_vnodes_after = get_vnodes_array(&vroot, vnodes_after);
	ck_assert(is_subset(vnodes, nr_vnodes, vnodes_after,
			    nr_vnodes_after, vnode_cmp));

	INIT_RB_ROOT(&vroot);
	for (int i = 0; i < 200; i++)
		node_to_vnodes(nodes + i, &vroot);
	nr_vnodes = get_vnodes_array(&vroot, vnodes);
	/* 1 node leave */
	INIT_RB_ROOT(&vroot);
	for (int i = 0; i < 199; i++)
		node_to_vnodes(nodes + i, &vroot);
	nr_vnodes_after = get_vnodes_array(&vroot, vnodes_after);
	ck_assert(is_subset(vnodes, nr_vnodes, vnodes_after,
			    nr_vnodes_after, vnode_cmp));
	/* 100 nodes leave */
	INIT_RB_ROOT(&vroot);
	for (int i = 50; i < 150; i++)
		node_to_vnodes(nodes + i, &vroot);
	nr_vnodes_after = get_vnodes_array(&vroot, vnodes_after);
	ck_assert(is_subset(vnodes, nr_vnodes, vnodes_after,
			    nr_vnodes_after, vnode_cmp));
}
END_TEST

static void gen_data_from_nodes(double *data, int idx)
{
	struct sd_node nodes[DATA_SIZE];
	struct sd_vnode *vnode;
	struct rb_root vroot;
	int nr_nodes;
	double *p = data;

	nr_nodes = gen_nodes(nodes, idx);
	INIT_RB_ROOT(&vroot);
	for (int i = 0; i < nr_nodes; i++)
		node_to_vnodes(nodes + i, &vroot);

	rb_for_each_entry(vnode, &vroot, rb)
		*p++ = vnode->hash;

	ck_assert_int_eq(p - data, DATA_SIZE);
}

START_TEST(test_nodes_dispersion)
{
	chi2_test(gen_data_from_nodes);
}
END_TEST

static size_t (*gen_disks)(struct disk *disks, int idx);

/* generate one disk who has many virtual disks */
static size_t gen_many_vdisks(struct disk *disks, int idx)
{
	memset(disks, 0, sizeof(*disks));

	snprintf(disks[0].path, sizeof(disks[0].path), "/%x", idx);
	disks[0].space = MD_VDISK_SIZE * DATA_SIZE;

	return 1;
}

static void disk1_setup(void)
{
	gen_disks = gen_many_vdisks;
}

/* generate many disk who have only one virtual disk */
static size_t gen_many_disks_one_vdisk(struct disk *disks, int idx)
{
	memset(disks, 0, sizeof(*disks) * DATA_SIZE);

	for (int i = 0; i < DATA_SIZE; i++) {
		snprintf(disks[i].path, sizeof(disks[i].path),
			 "/%x/%x", idx, i);
		disks[i].space = MD_VDISK_SIZE;
	}

	return DATA_SIZE;
}

static void disk2_setup(void)
{
	gen_disks = gen_many_disks_one_vdisk;
}

/* generate many disk who have some virtual disks */
static size_t gen_many_disks_some_vdisks(struct disk *disks, int idx)
{
	memset(disks, 0, sizeof(*disks) * DATA_SIZE);

	for (int i = 0; i < DATA_SIZE / 4; i++) {
		snprintf(disks[i].path, sizeof(disks[i].path),
			 "/%x/%x", idx, i);
		disks[i].space = MD_VDISK_SIZE * 4;
	}

	return DATA_SIZE / 4;
}

static void disk3_setup(void)
{
	gen_disks = gen_many_disks_some_vdisks;
}

static size_t get_vdisks_array(struct vdisk *vdisks)
{
	struct vdisk *vdisk;
	size_t nr = 0;

	rb_for_each_entry(vdisk, &md.vroot, rb) {
		nr++;
		*vdisks++ = *vdisk;
	}

	return nr;
}

START_TEST(test_disks_update)
{
	size_t nr_vdisks;
	size_t nr_vdisks_after;
	struct disk *disks;
	struct vdisk vdisks[DATA_SIZE];
	struct vdisk vdisks_after[DATA_SIZE];

	disks = (struct disk *)malloc(sizeof(struct disk) * DATA_SIZE);

	gen_disks(disks, 0);

	INIT_RB_ROOT(&md.vroot);
	create_vdisks(disks);
	nr_vdisks = get_vdisks_array(vdisks);
	/* add 1 disk */
	create_vdisks(disks + 1);
	nr_vdisks_after = get_vdisks_array(vdisks_after);
	ck_assert(is_subset(vdisks_after, nr_vdisks_after, vdisks,
			    nr_vdisks, vdisk_cmp));

	INIT_RB_ROOT(&md.vroot);
	for (int i = 0; i < 30; i++)
		create_vdisks(disks + i);
	nr_vdisks = get_vdisks_array(vdisks);
	/* add 1 disk */
	create_vdisks(disks + 30);
	nr_vdisks_after = get_vdisks_array(vdisks_after);
	ck_assert(is_subset(vdisks_after, nr_vdisks_after, vdisks,
			    nr_vdisks, vdisk_cmp));
	/* add 20 disks */
	for (int i = 31; i < 50; i++)
		create_vdisks(disks + i);
	nr_vdisks_after = get_vdisks_array(vdisks_after);
	ck_assert(is_subset(vdisks_after, nr_vdisks_after, vdisks,
			    nr_vdisks, vdisk_cmp));

	INIT_RB_ROOT(&md.vroot);
	create_vdisks(disks);
	create_vdisks(disks + 1);
	nr_vdisks = get_vdisks_array(vdisks);
	/* remove 1 disk */
	remove_vdisks(disks);
	nr_vdisks_after = get_vdisks_array(vdisks_after);
	ck_assert(is_subset(vdisks, nr_vdisks, vdisks_after,
			    nr_vdisks_after, vdisk_cmp));

	INIT_RB_ROOT(&md.vroot);
	for (int i = 0; i < 50; i++)
		create_vdisks(disks + i);
	nr_vdisks = get_vdisks_array(vdisks);
	/* remove 1 disk */
	remove_vdisks(disks);
	nr_vdisks_after = get_vdisks_array(vdisks_after);
	ck_assert(is_subset(vdisks, nr_vdisks, vdisks_after,
			    nr_vdisks_after, vdisk_cmp));
	/* remove 20 disks */
	for (int i = 1; i < 10; i++)
		remove_vdisks(disks + i);
	for (int i = 40; i < 50; i++)
		remove_vdisks(disks + i);
	nr_vdisks_after = get_vdisks_array(vdisks_after);
	ck_assert(is_subset(vdisks, nr_vdisks, vdisks_after,
			    nr_vdisks_after, vdisk_cmp));


	free(disks);
}
END_TEST

static void gen_data_from_disks(double *data, int idx)
{
	struct disk *disks;
	struct vdisk *vdisk;
	int nr_disks;
	double *p = data;

	disks = (struct disk *)malloc(sizeof(struct disk) * DATA_SIZE);

	nr_disks = gen_disks(disks, idx);
	INIT_RB_ROOT(&md.vroot);
	for (int i = 0; i < nr_disks; i++)
		create_vdisks(disks + i);

	rb_for_each_entry(vdisk, &md.vroot, rb)
		*p++ = vdisk->hash;

	ck_assert_int_eq(p - data, DATA_SIZE);

	free(disks);
}

START_TEST(test_disks_dispersion)
{
	chi2_test(gen_data_from_disks);
}
END_TEST

static void (*gen_objects)(uint64_t *objects, int idx);

/* generate one vdi with many data objects */
static void gen_data_objects(uint64_t *objects, int idx)
{
	for (int i = 0; i < DATA_SIZE; i++) {
		uint64_t oid = vid_to_data_oid(idx, i);
		objects[i] = sd_hash_oid(oid);
	}
}

static void object1_setup(void)
{
	gen_objects = gen_data_objects;
}

/* generate many vdi objects */
static void gen_vdi_objects(uint64_t *objects, int idx)
{
	for (int i = 0; i < DATA_SIZE; i++) {
		uint64_t oid = vid_to_data_oid(idx * DATA_SIZE + i, 0);
		objects[i] = sd_hash_oid(oid);
	}
}

static void object2_setup(void)
{
	gen_objects = gen_vdi_objects;
}

static void gen_data_from_objects(double *data, int idx)
{
	uint64_t objects[DATA_SIZE];

	gen_objects(objects, idx);

	for (int i = 0; i < DATA_SIZE; i++)
		data[i] = objects[i];
}

START_TEST(test_objects_dispersion)
{
	chi2_test(gen_data_from_objects);
}
END_TEST

static Suite *test_suite(void)
{
	Suite *s = suite_create("test hash");

	TCase *tc_basic1 = tcase_create("sd_hash");
	TCase *tc_basic2 = tcase_create("sd_hash_next");
	TCase *tc_nodes1 = tcase_create("many vnodes");
	TCase *tc_nodes2 = tcase_create("many daemons with one vnode");
	TCase *tc_nodes3 = tcase_create("many daemons with some vnodes");
	TCase *tc_nodes4 = tcase_create("many nodes with one vnode");
	TCase *tc_nodes5 = tcase_create("many nodes with some vnodes");
	TCase *tc_disks1 = tcase_create("many vdisks on one disk");
	TCase *tc_disks2 = tcase_create("many disks with one vdisk");
	TCase *tc_disks3 = tcase_create("many disks with some vdisks");
	TCase *tc_objects1 = tcase_create("many data objects");
	TCase *tc_objects2 = tcase_create("many vdi objects");

	tcase_add_checked_fixture(tc_basic1, basic1_setup, NULL);
	tcase_add_checked_fixture(tc_basic2, basic2_setup, NULL);
	tcase_add_checked_fixture(tc_nodes1, node1_setup, NULL);
	tcase_add_checked_fixture(tc_nodes2, node2_setup, NULL);
	tcase_add_checked_fixture(tc_nodes3, node3_setup, NULL);
	tcase_add_checked_fixture(tc_nodes4, node4_setup, NULL);
	tcase_add_checked_fixture(tc_nodes5, node5_setup, NULL);
	tcase_add_checked_fixture(tc_disks1, disk1_setup, NULL);
	tcase_add_checked_fixture(tc_disks2, disk2_setup, NULL);
	tcase_add_checked_fixture(tc_disks3, disk3_setup, NULL);
	tcase_add_checked_fixture(tc_objects1, object1_setup, NULL);
	tcase_add_checked_fixture(tc_objects2, object2_setup, NULL);

	tcase_add_test(tc_basic1, test_basic_dispersion);
	tcase_add_test(tc_basic2, test_basic_dispersion);
	tcase_add_test(tc_nodes1, test_nodes_dispersion);
	tcase_add_test(tc_nodes2, test_nodes_update);
	tcase_add_test(tc_nodes2, test_nodes_dispersion);
	tcase_add_test(tc_nodes3, test_nodes_update);
	tcase_add_test(tc_nodes3, test_nodes_dispersion);
	tcase_add_test(tc_nodes4, test_nodes_update);
	tcase_add_test(tc_nodes4, test_nodes_dispersion);
	tcase_add_test(tc_nodes5, test_nodes_update);
	tcase_add_test(tc_nodes5, test_nodes_dispersion);
	tcase_add_test(tc_disks1, test_disks_dispersion);
	tcase_add_test(tc_disks2, test_disks_update);
	tcase_add_test(tc_disks2, test_disks_dispersion);
	tcase_add_test(tc_disks3, test_disks_update);
	tcase_add_test(tc_disks3, test_disks_dispersion);
	tcase_add_test(tc_objects1, test_objects_dispersion);
	tcase_add_test(tc_objects2, test_objects_dispersion);

	suite_add_tcase(s, tc_basic1);
	suite_add_tcase(s, tc_basic2);
	suite_add_tcase(s, tc_nodes1);
	suite_add_tcase(s, tc_nodes2);
	suite_add_tcase(s, tc_nodes3);
	suite_add_tcase(s, tc_disks1);
	suite_add_tcase(s, tc_disks2);
	suite_add_tcase(s, tc_objects1);
	suite_add_tcase(s, tc_objects2);

	return s;
}

int main(void)
{
	struct system_info __sys;
	int number_failed;
	sys = &__sys;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
