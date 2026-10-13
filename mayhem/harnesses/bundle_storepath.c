/*
 * mayhem/harnesses/bundle_storepath.c — fuzz/bundle.c with a system config that sets the casync
 * store path ([casync] storepath=), the way a target's system.conf does, and the context torn
 * down after each bundle (r_context_clean(), which frees the config).
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
	g_autoptr(GError) error = NULL;

	fuzz_set_logging_func();

	tmpdir = g_dir_make_tmp("rauc-XXXXXX", NULL);
	g_assert_nonnull(tmpdir);

	r_context_conf()->certpath = g_strdup("test/openssl-ca/dev/autobuilder-1.cert.pem");
	r_context_conf()->keypath = g_strdup("test/openssl-ca/dev/private/autobuilder-1.pem");
	r_context();
	r_context()->config->store_path = g_strdup("/var/lib/rauc/store.castr");

	bundlename = g_build_filename(tmpdir, "fuzz-bundle.raucb", NULL);
	g_assert_nonnull(bundlename);
	g_file_set_contents(bundlename, (gchar*)data, size, &error);

	check_one(bundlename);

	r_context_clean();
	g_remove(bundlename);
	g_remove(tmpdir);

	return 0;
}
