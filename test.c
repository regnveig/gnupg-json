#include "gpgme_json.h"

gpgme_error_t set_context(gpgme_ctx_t *ctx) {
	gpgme_error_t err;
	gpgme_check_version(NULL);
	err = gpgme_new(ctx);
	if (err) return err;
	const char *engine = gpgme_get_dirinfo("gpg-name\0");
	const char *home_dir = NULL;
	err = gpgme_ctx_set_engine_info(*ctx, GPGME_PROTOCOL_OPENPGP, engine, home_dir);
	if (err) return err;
	gpgme_set_armor(*ctx, 1);
	gpgme_set_offline(*ctx, 1);
	gpgme_signers_clear(*ctx);
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t test_key() {
	gpgme_ctx_t ctx;
	gpgme_key_t key;
	gpgme_data_t json;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_SIGS | GPGME_KEYLIST_MODE_SIG_NOTATIONS | GPGME_KEYLIST_MODE_WITH_TOFU | GPGME_KEYLIST_MODE_WITH_KEYGRIP | GPGME_KEYLIST_MODE_VALIDATE | GPGME_KEYLIST_MODE_WITH_SECRET);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_get_key(ctx, "A1662AA073AE46CD6FE88CDB8D12EDFB66827FA2\0", &key, 0);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_key(key, json);
		gpgme_key_release(key);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

gpgme_error_t test_data() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t json;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new_from_file(&data, ".test_signed.asc\0", 1);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_data(data, json);
		gpgme_data_release(data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

gpgme_error_t test_verify() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t plain;
	gpgme_data_t json;
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
		err = gpgme_data_new_from_file(&data, ".test_signed.asc\0", 1);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_op_verify(ctx, data, NULL, plain);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
		err = jsonify_gpgme_verify_result(result, json);
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
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

gpgme_error_t test_sign() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t signed_message;
	gpgme_data_t json;
	gpgme_key_t key;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&signed_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_get_key(ctx, "A1662AA073AE46CD6FE88CDB8D12EDFB66827FA2\0", &key, 0);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_signers_add(ctx, key);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new_from_file(&data, ".test_plain.txt\0", 1);
	}
//	if (err == GPG_ERR_NO_ERROR) {
//		 err = gpgme_sig_notation_add(ctx, "jerk\0", "you\0", GPGME_SIG_NOTATION_HUMAN_READABLE);
//	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_op_sign(ctx, data, signed_message, GPGME_SIG_MODE_CLEAR);
		gpgme_key_release(key);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_sign_result_t result = gpgme_op_sign_result(ctx);
		err = jsonify_gpgme_sign_result(result, json);
		gpgme_data_release(data);
		gpgme_data_release(signed_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

gpgme_error_t test_ctx() {
	gpgme_ctx_t ctx;
	gpgme_data_t json;
	
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
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

gpgme_error_t test_encrypt() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t encrypted_message;
	gpgme_data_t json;
	gpgme_key_t key;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&encrypted_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_get_key(ctx, "A1662AA073AE46CD6FE88CDB8D12EDFB66827FA2\0", &key, 0);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new_from_file(&data, ".test_plain.txt\0", 1);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_key_t keys[] = {key, NULL};
		err = gpgme_op_encrypt(ctx, keys, GPGME_ENCRYPT_NO_COMPRESS, data, encrypted_message);
		gpgme_key_release(key);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_encrypt_result_t result = gpgme_op_encrypt_result(ctx);
		err = jsonify_gpgme_encrypt_result(result, json);
		gpgme_data_release(data);
		gpgme_data_release(encrypted_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

gpgme_error_t test_decrypt() {
	gpgme_ctx_t ctx;
	gpgme_data_t data;
	gpgme_data_t decrypted_message;
	gpgme_data_t json;
	gpgme_error_t err = set_context(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&json);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&data);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new(&decrypted_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_data_new_from_file(&data, ".test_encrypted.asc\0", 1);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = gpgme_op_decrypt(ctx, data, decrypted_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_decrypt_result_t result = gpgme_op_decrypt_result(ctx);
		err = jsonify_gpgme_decrypt_result(result, json);
		gpgme_data_release(data);
		gpgme_data_release(decrypted_message);
	}
	if (err == GPG_ERR_NO_ERROR) {
		ssize_t length = gpgme_data_write(json, "\0", 1);
		if (length != 1) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		char *plaintext = gpgme_data_release_and_get_mem(json, NULL);
		fprintf(stdout, "%s\n", plaintext);
		gpgme_free(plaintext);
		gpgme_release(ctx);
	} else {
		gpgme_data_release(json);
	}
	return err;
}

int main() {
	fprintf(stdout, "\"TEST KEY\"\n");
	gpgme_error_t err = test_key();
	fprintf(stdout, "\"TEST CTX\"\n");
	if (err == GPG_ERR_NO_ERROR) {
		err = test_ctx();
	}
	fprintf(stdout, "\"TEST DATA\"\n");
	if (err == GPG_ERR_NO_ERROR) {
		err = test_data();
	}
	fprintf(stdout, "\"TEST VERIFY\"\n");
	if (err == GPG_ERR_NO_ERROR) {
		err = test_verify();
	}
	fprintf(stdout, "\"TEST SIGN\"\n");
	if (err == GPG_ERR_NO_ERROR) {
		err = test_sign();
	}
	fprintf(stdout, "\"TEST ENCRYPT\"\n");
	if (err == GPG_ERR_NO_ERROR) {
		err = test_encrypt();
	}
	fprintf(stdout, "\"TEST DECRYPT\"\n");
	if (err == GPG_ERR_NO_ERROR) {
		err = test_decrypt();
	}
	fprintf(stdout, "\"%s\"\n", gpgme_strerror(err));
	return 0;
} 
