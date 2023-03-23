#include "gpgme_json.h"

gpgme_error_t set_context(gpgme_ctx_t *ctx) {
	gpgme_error_t err;
	gpgme_check_version(NULL);
	err = gpgme_new(ctx);
	if (err) return err;
	const char *engine = gpgme_get_dirinfo("gpg-name");
	const char *home_dir = NULL;
	err = gpgme_ctx_set_engine_info(*ctx, GPGME_PROTOCOL_OPENPGP, engine, home_dir);
	if (err) return err;
	gpgme_set_armor(*ctx, 1);
	gpgme_set_offline(*ctx, 1);
	gpgme_signers_clear(*ctx);
	return GPG_ERR_NO_ERROR;
}

int main() {
	gpgme_error_t err;
	gpgme_ctx_t ctx;
	err = set_context(&ctx);
	err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_SIGS | GPGME_KEYLIST_MODE_SIG_NOTATIONS | GPGME_KEYLIST_MODE_WITH_TOFU | GPGME_KEYLIST_MODE_WITH_KEYGRIP | GPGME_KEYLIST_MODE_VALIDATE | GPGME_KEYLIST_MODE_WITH_SECRET);
	gpgme_data_t plain;
	err = gpgme_data_new(&plain);
	gpgme_data_t plain2;
	err = gpgme_data_new(&plain2);
	gpgme_data_t dh;
	err = gpgme_data_new_from_file(&dh, "testkey.asc", 1);
	err = gpgme_op_verify(ctx, dh, NULL, plain2);
	gpgme_verify_result_t res = gpgme_op_verify_result(ctx);
	gpgme_key_t key;
	err = gpgme_get_key(ctx, "A1662AA073AE46CD6FE88CDB8D12EDFB66827FA2", &key, 0);
	jsonify_gpgme_key(key, plain);
	gpgme_data_write(plain, "\0", 1);
	char *plaintext = gpgme_data_release_and_get_mem(plain, NULL);
	fprintf(stderr, "%s", plaintext);
	gpgme_free(dh);
	gpgme_free(plaintext);
	gpgme_release(ctx);
} 
