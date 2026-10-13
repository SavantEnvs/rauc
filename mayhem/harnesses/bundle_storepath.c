/*
 * mayhem/harnesses/bundle_storepath.c — fuzz/bundle.c with a choice of system config: the input's
 * first byte selects the config, the rest is the bundle. The selector 0x5a is a system.conf with a
 * casync store path ([casync] storepath=), as on a target; any other value is the default config,
 * as in fuzz/bundle.c. The bundle is checked twice, the second time after the context was marked
 * for reconfiguration (r_context_conf()), as a long-running service does between two requests:
 * the context re-reads the system config inside check_bundle(), freeing the previous config.
 *
 * fuzz/bundle.c runs on a default config, whose store_path is NULL, so check_bundle() never takes
 * its "store path from the config" branch and the ownership of that string is never exercised.
 */
#include <stdio.h>
#include <locale.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <config_file.h>
#include <context.h>
#include <bundle.h>

#include "fuzz.h"

static const gchar *system_conf =
	"[system]\n"
	"compatible=fuzz\n"
	"bootloader=barebox\n"
	"statusfile=per-slot\n"
	"\n"
	"[casync]\n"
	"storepath=/var/lib/rauc/store.castr\n";

static void check_one(const gchar *bundlename)
{
	g_autoptr(RaucBundle) bundle = NULL;
	g_autoptr(GError) error = NULL;

	(void) check_bundle(bundlename, &bundle, CHECK_BUNDLE_NO_VERIFY, NULL, &error);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *bundlename = NULL;
	g_autofree gchar *confname = NULL;
	g_autoptr(GError) error = NULL;

	if (size < 1)
		return -1;
	uint8_t selector = data[0];
	data++;
	size--;

	fuzz_set_logging_func();

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	bundlename = g_build_filename(tmpdir, "fuzz-bundle.raucb", NULL);
	g_assert_nonnull(bundlename);
	g_file_set_contents(bundlename, (gchar*)data, size, &error);

	confname = g_build_filename(tmpdir, "system.conf", NULL);
	g_assert_nonnull(confname);

	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/autobuilder-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/autobuilder-1.pem");
	if (selector == 0x5a) {
		g_clear_error(&error);
		g_assert_true(g_file_set_contents(confname, system_conf, -1, &error));
		r_context_conf()->configpath = g_strdup(confname);
	}

	check_one(bundlename);

	r_context_conf();
	check_one(bundlename);

	r_context_clean();
	g_remove(confname);
	g_remove(bundlename);
	g_remove(tmpdir);

	return 0;
}
