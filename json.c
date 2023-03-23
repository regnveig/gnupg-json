#include "json.h"

gpgme_error_t jsonify_left_brace(gpgme_data_t dh) {
	if (gpgme_data_write(dh, "{\0", 1) != 1) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_right_brace(gpgme_data_t dh) {
	if (gpgme_data_write(dh, "}\0", 1) != 1) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_left_square_bracket(gpgme_data_t dh) {
	if (gpgme_data_write(dh, "[\0", 1) != 1) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_right_square_bracket(gpgme_data_t dh) {
	if (gpgme_data_write(dh, "]\0", 1) != 1) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_comma(gpgme_data_t dh) {
	if (gpgme_data_write(dh, ", \0", 2) != 2) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_colon(gpgme_data_t dh) {
	if (gpgme_data_write(dh, ": \0", 2) != 2) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_bool(int num, gpgme_data_t dh) {
	if (num) {
		if (gpgme_data_write(dh, "true\0", 4) != 4) return GPG_ERR_USER_1;
	} else {
		if (gpgme_data_write(dh, "false\0", 5) != 5) return GPG_ERR_USER_1;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_string(const char *str, gpgme_data_t dh) {
	if (gpgme_data_write(dh, C_QUOTE, C_QUOTE_LEN) != C_QUOTE_LEN) return GPG_ERR_USER_1;
	const char *index_start = str;
	const char *index_end = str;
	while(*index_end != '\0') {
		index_end++;
		if ((*index_end == *C_SLASH) || (*index_end == *C_QUOTE)) {
			size_t len = index_end - index_start;
			if (gpgme_data_write(dh, index_start, len) != len) return GPG_ERR_USER_1;
			if (gpgme_data_write(dh, C_SLASH, C_SLASH_LEN) != C_SLASH_LEN) return GPG_ERR_USER_1;
			index_start = index_end;
		}
	}
	size_t len = index_end - index_start;
	if (gpgme_data_write(dh, index_start, len) != len) return GPG_ERR_USER_1;
	if (gpgme_data_write(dh, C_QUOTE, C_QUOTE_LEN) != C_QUOTE_LEN) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_int(int num, gpgme_data_t dh) {
	size_t len;
	if (abs(num)) {
		len = floor(log10(abs(num)) + 2) * sizeof(char);
		if (num < 0) len++;
	} else {
		len = 2;
	}
	char str[len];
	sprintf(str, "%d%c", num, '\0');
	if (gpgme_data_write(dh, str, len - 1) != (len - 1)) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_null(gpgme_data_t dh) {
	if (gpgme_data_write(dh, "null\0", 4) != 4) return GPG_ERR_USER_1;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_key_bool(const char *key, int num, gpgme_data_t dh, int comma) {
	gpgme_error_t err;
	err = jsonify_string(key, dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_bool(num, dh);
	if (err) return err;
	if (comma) {
		err = jsonify_comma(dh);
		if (err) return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_key_string(const char *key, const char *str, gpgme_data_t dh, int comma) {
	gpgme_error_t err;
	err = jsonify_string(key, dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_string(str, dh);
	if (err) return err;
	if (comma) {
		err = jsonify_comma(dh);
		if (err) return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_key_int(const char *key, int num, gpgme_data_t dh, int comma) {
	gpgme_error_t err;
	err = jsonify_string(key, dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_int(num, dh);
	if (err) return err;
	if (comma) {
		err = jsonify_comma(dh);
		if (err) return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_key_null(const char *key, gpgme_data_t dh, int comma) {
	gpgme_error_t err;
	err = jsonify_string(key, dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_null(dh);
	if (err) return err;
	if (comma) {
		err = jsonify_comma(dh);
		if (err) return err;
	}
	return GPG_ERR_NO_ERROR;
}
