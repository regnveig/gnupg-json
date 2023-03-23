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

void test_key() {
	gpgme_ctx_t ctx;
	gpgme_key_t key;
	gpgme_data_t json;
	char *plaintext;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_SIGS | GPGME_KEYLIST_MODE_SIG_NOTATIONS | GPGME_KEYLIST_MODE_WITH_TOFU | GPGME_KEYLIST_MODE_WITH_KEYGRIP | GPGME_KEYLIST_MODE_VALIDATE | GPGME_KEYLIST_MODE_WITH_SECRET);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_get_key(ctx, "A1662AA073AE46CD6FE88CDB8D12EDFB66827FA2", &key, 0);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_key(key, json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_key_release(key);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	
}

void test_data() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t json;
	char *plaintext;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new_from_file(&data, ".test_signed.asc", 1);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_data(data, json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_data_release(data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
}

void test_verify() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t plain;
	gpgme_data_t json;
	char *plaintext;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&plain);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new_from_file(&data, ".test_signed.asc", 1);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_op_verify(ctx, data, NULL, plain);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
		err = jsonify_gpgme_verify_result(result, json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_data_release(data);
		gpgme_data_release(plain);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
}

void test_ctx() {
	gpgme_ctx_t ctx;
	gpgme_data_t json;
	char *plaintext;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_ctx(ctx, json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
}

int main() {
	test_key();
	test_ctx();
	test_data();
	test_verify();
	return 0;
} 
