#include "json.h"

gpgme_error_t jsonify_left_brace(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_LEFT_BRACE, C_LEFT_BRACE_LEN);
	if (length != C_LEFT_BRACE_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_right_brace(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_RIGHT_BRACE, C_RIGHT_BRACE_LEN);
	if (length != C_RIGHT_BRACE_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_left_square_bracket(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_LEFT_SQUARE_BRACKET, C_LEFT_SQUARE_BRACKET_LEN);
	if (length != C_LEFT_SQUARE_BRACKET_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_right_square_bracket(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_RIGHT_SQUARE_BRACKET, C_RIGHT_SQUARE_BRACKET_LEN);
	if (length != C_RIGHT_SQUARE_BRACKET_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_comma(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_COMMA, C_COMMA_LEN);
	if (length != C_COMMA_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_colon(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_COLON, C_COLON_LEN);
	if (length != C_COLON_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_bool(int num, gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length;
	if (num) {
		length = gpgme_data_write(dh, C_TRUE_STRING, C_TRUE_STRING_LEN);
		if (length != C_TRUE_STRING_LEN) {
			err = GPG_ERR_ENOMEM;
		}
	} else {
		length = gpgme_data_write(dh, C_FALSE_STRING, C_FALSE_STRING_LEN);
		if (length != C_FALSE_STRING_LEN) {
			err = GPG_ERR_ENOMEM;
		}
	}
	return err;
}

gpgme_error_t jsonify_string(const char *str, gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length = gpgme_data_write(dh, C_QUOTE, C_QUOTE_LEN);
	if (length != C_QUOTE_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	const char *index_start = str;
	const char *index_end = str;
	if (err == GPG_ERR_NO_ERROR) {
		while (*index_end != '\0') {
			index_end++;
			if ((*index_end == *C_SLASH) || (*index_end == *C_QUOTE)) {
				size_t len = index_end - index_start;
				length = gpgme_data_write(dh, index_start, len);
				if (length != len) {
					err = GPG_ERR_ENOMEM;
					break;
				}
				length = gpgme_data_write(dh, C_SLASH, C_SLASH_LEN);
				if (length != C_SLASH_LEN) {
					err = GPG_ERR_ENOMEM;
					break;
				}
				index_start = index_end;
			}
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		size_t len = index_end - index_start;
		length = gpgme_data_write(dh, index_start, len);
		if (length != len) {
			err = GPG_ERR_ENOMEM;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		length = gpgme_data_write(dh, C_QUOTE, C_QUOTE_LEN);
		if (length != C_QUOTE_LEN) {
			err = GPG_ERR_ENOMEM;
		}
	}
	return err;
}

gpgme_error_t jsonify_int(int num, gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t len;
	if (abs(num) > 0) {
		len = floor(log10(abs(num)) + 2);
		if (num < 0) {
			len++;
		}
	} else {
		len = 2;
	}
	char str[len];
	int offset = snprintf(str, len * sizeof(char), "%d%c", num, '\0');
	if (offset != len) {
		err = GPG_ERR_GENERAL;
	}
	size_t length = gpgme_data_write(dh, str, len - 1);
	if (length != (len - 1)) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_null(gpgme_data_t dh) {
	gpgme_error_t err = GPG_ERR_NO_ERROR;
	size_t length =  gpgme_data_write(dh, C_NULL_STRING, C_NULL_STRING_LEN);
	if (length != C_NULL_STRING_LEN) {
		err = GPG_ERR_ENOMEM;
	}
	return err;
}

gpgme_error_t jsonify_key_bool(const char *key, int num, gpgme_data_t dh, int comma) {
	gpgme_error_t err = jsonify_string(key, dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_bool(num, dh);
	}
	if (comma && (err == GPG_ERR_NO_ERROR)) {
		err = jsonify_comma(dh);
	}
	return err;
}

gpgme_error_t jsonify_key_string(const char *key, const char *str, gpgme_data_t dh, int comma) {
	gpgme_error_t err = jsonify_string(key, dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		jsonify_string(str, dh);
	}
	if (comma && (err == GPG_ERR_NO_ERROR)) {
		err = jsonify_comma(dh);
	}
	return err;
}

gpgme_error_t jsonify_key_int(const char *key, int num, gpgme_data_t dh, int comma) {
	gpgme_error_t err = jsonify_string(key, dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_int(num, dh);
	}
	if (comma && (err == GPG_ERR_NO_ERROR)) {
		err = jsonify_comma(dh);
	}
	return err;
}

gpgme_error_t jsonify_key_null(const char *key, gpgme_data_t dh, int comma) {
	gpgme_error_t err = jsonify_string(key, dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_null(dh);
	}
	if (comma && (err == GPG_ERR_NO_ERROR)) {
		err = jsonify_comma(dh);
	}
	return err;
}
