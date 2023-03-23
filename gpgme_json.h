#ifndef GPGME_JSON_H
#define GPGME_JSON_H

#include "json.h"

// const to strings
const char *gpgme_validity_string(gpgme_validity_t val);
const char *gpgme_pinentry_mode_string(gpgme_pinentry_mode_t val);
const char *gpgme_data_encoding_string(gpgme_data_encoding_t val);
const char *gpgme_data_type_string(gpgme_data_type_t val);
const char *pka_trust_string(unsigned int val);

// jsonify structs
gpgme_error_t jsonify_gpgme_error(gpgme_error_t error, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_subkey(gpgme_subkey_t key, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_sig_notation(gpgme_sig_notation_t note, gpgme_data_t dh); // TODO Not implemented
gpgme_error_t jsonify_gpgme_tofu_info(gpgme_tofu_info_t info, gpgme_data_t dh); // TODO Not implemented
gpgme_error_t jsonify_gpgme_key_sig(gpgme_key_sig_t sig, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_user_id(gpgme_user_id_t uid, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_key(gpgme_key_t key, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_engine_info(gpgme_engine_info_t engine, gpgme_data_t dh);
gpgme_error_t jsonify_include_certs(int num, gpgme_data_t dh);
gpgme_error_t jsonify_ctx(gpgme_ctx_t ctx, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_data(gpgme_data_t data, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_signature(gpgme_signature_t sig, gpgme_data_t dh);
gpgme_error_t jsonify_gpgme_verify_result(gpgme_verify_result_t result, gpgme_data_t dh);

#endif
