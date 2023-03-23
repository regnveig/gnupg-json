#include <gpgme.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#ifndef JSON_H
#define JSON_H

static const char * C_QUOTE = "\""; static const int C_QUOTE_LEN = 1;
static const char * C_SLASH = "\\"; static const int C_SLASH_LEN = 1;

// JSON elements
gpgme_error_t jsonify_left_brace(gpgme_data_t dh);
gpgme_error_t jsonify_right_brace(gpgme_data_t dh);
gpgme_error_t jsonify_left_square_bracket(gpgme_data_t dh);
gpgme_error_t jsonify_right_square_bracket(gpgme_data_t dh);
gpgme_error_t jsonify_comma(gpgme_data_t dh);
gpgme_error_t jsonify_colon(gpgme_data_t dh);

// JSON values
gpgme_error_t jsonify_bool(int num, gpgme_data_t dh);
gpgme_error_t jsonify_string(const char *str, gpgme_data_t dh);
gpgme_error_t jsonify_int(int num, gpgme_data_t dh);
gpgme_error_t jsonify_null(gpgme_data_t dh);

// JSON key-value
gpgme_error_t jsonify_key_bool(const char *key, int num, gpgme_data_t dh, int comma);
gpgme_error_t jsonify_key_string(const char *key, const char *str, gpgme_data_t dh, int comma);
gpgme_error_t jsonify_key_int(const char *key, int num, gpgme_data_t dh, int comma);
gpgme_error_t jsonify_key_null(const char *key, gpgme_data_t dh, int comma);

#endif
