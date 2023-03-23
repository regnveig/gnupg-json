#include "gpgme_json.h"

/* CONST TO STRINGS */

const char *gpgme_validity_string(gpgme_validity_t val) {
	switch(val) {
		case GPGME_VALIDITY_UNKNOWN: return "unknown";
		case GPGME_VALIDITY_UNDEFINED: return "undefined";
		case GPGME_VALIDITY_NEVER: return "never";
		case GPGME_VALIDITY_MARGINAL: return "marginal";
		case GPGME_VALIDITY_FULL: return "full";
		case GPGME_VALIDITY_ULTIMATE: return "ultimate";
	}
	return "-";
}

const char *gpgme_pinentry_mode_string(gpgme_pinentry_mode_t val) {
	switch(val) {
		case GPGME_PINENTRY_MODE_DEFAULT: return "default";
		case GPGME_PINENTRY_MODE_ASK: return "ask";
		case GPGME_PINENTRY_MODE_CANCEL: return "cancel";
		case GPGME_PINENTRY_MODE_ERROR: return "error";
		case GPGME_PINENTRY_MODE_LOOPBACK: return "loopback";
	}
	return "-";
}

const char *gpgme_data_encoding_string(gpgme_data_encoding_t val) {
	switch(val) {
		case GPGME_DATA_ENCODING_NONE: return "none";
		case GPGME_DATA_ENCODING_BINARY: return "binary";
		case GPGME_DATA_ENCODING_BASE64: return "base64";
		case GPGME_DATA_ENCODING_ARMOR: return "armor";
		case GPGME_DATA_ENCODING_MIME: return "mime";
		case GPGME_DATA_ENCODING_URL: return "url";
		case GPGME_DATA_ENCODING_URL0: return "url0";
		case GPGME_DATA_ENCODING_URLESC: return "urlesc";
	}
	return "-";
}

const char *gpgme_data_type_string(gpgme_data_type_t val) {
	switch(val) {
		case GPGME_DATA_TYPE_INVALID: return "invalid";
		case GPGME_DATA_TYPE_UNKNOWN: return "unknown";
		case GPGME_DATA_TYPE_PGP_SIGNED: return "pgp_signed";
		case GPGME_DATA_TYPE_PGP_ENCRYPTED: return "pgp_encrypted";
		case GPGME_DATA_TYPE_PGP_SIGNATURE: return "pgp_signature";
		case GPGME_DATA_TYPE_PGP_OTHER: return "pgp_other";
		case GPGME_DATA_TYPE_PGP_KEY: return "pgp_key";
		case GPGME_DATA_TYPE_CMS_SIGNED: return "cms_signed";
		case GPGME_DATA_TYPE_CMS_ENCRYPTED: return "cms_encrypted";
		case GPGME_DATA_TYPE_CMS_OTHER: return "cms_other";
		case GPGME_DATA_TYPE_X509_CERT: return "x509_cert";
		case GPGME_DATA_TYPE_PKCS12: return "pkcs12";
	}
	return "-";
}

const char *pka_trust_string(unsigned int val) {
	switch(val) {
		case 0: return "no_pka_info";
		case 1: return "pka_verification_failed";
		case 2: return "pke_verification_success"; 
	}
	return "-";
}

/* JSONIFY STRUCTS */

gpgme_error_t jsonify_gpgme_error(gpgme_error_t error, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// code
	err = jsonify_key_int("code", error, dh, 1);
	if (err) return err;
	// desc
	err = jsonify_key_string("description", gpgme_strerror(error), dh, 0);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_subkey(gpgme_subkey_t key, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// revoked ?
	err = jsonify_key_bool("revoked", key->revoked, dh, 1);
	if (err) return err;
	// expired ?
	err = jsonify_key_bool("expired", key->expired, dh, 1);
	if (err) return err;
	// disabled ?
	err = jsonify_key_bool("disabled", key->disabled, dh, 1);
	if (err) return err;
	// invalid ?
	err = jsonify_key_bool("invalid", key->invalid, dh, 1);
	if (err) return err;
	// can encrypt ?
	err = jsonify_key_bool("can_encrypt", key->can_encrypt, dh, 1);
	if (err) return err;
	// can sign ?
	err = jsonify_key_bool("can_sign", key->can_sign, dh, 1);
	if (err) return err;
	// can certify ?
	err = jsonify_key_bool("can_certify", key->can_certify, dh, 1);
	if (err) return err;
	// can authenticate ?
	err = jsonify_key_bool("can_authenticate", key->can_authenticate, dh, 1);
	if (err) return err;
	// is qualified ?
	err = jsonify_key_bool("is_qualified", key->is_qualified, dh, 1);
	if (err) return err;
	// is DE VS?
	err = jsonify_key_bool("is_de_vs", key->is_de_vs, dh, 1);
	if (err) return err;
	// is secret ?
	err = jsonify_key_bool("secret", key->secret, dh, 1);
	if (err) return err;
	// algo
	err = jsonify_key_string("pubkey_algo", gpgme_pubkey_algo_name(key->pubkey_algo), dh, 1);
	if (err) return err;
	// length
	err = jsonify_key_int("length", key->length, dh, 1);
	if (err) return err;
	// keyid
	err = jsonify_key_string("keyid", key->keyid, dh, 1);
	if (err) return err;
	// fpr
	err = jsonify_key_string("fingerprint", key->fpr, dh, 1);
	if (err) return err;
	// keygrip
	if (key->keygrip) err = jsonify_key_string("keygrip", key->keygrip, dh, 1);
	else err = jsonify_key_null("keygrip", dh, 1);
	if (err) return err;
	// timestamp
	err = jsonify_key_int("timestamp", key->timestamp, dh, 1);
	if (err) return err;
	// expires
	err = jsonify_key_int("expires", key->expires, dh, 1);
	if (err) return err;
	// is cardkey ?
	err = jsonify_key_bool("is_cardkey", key->is_cardkey, dh, 1);
	if (err) return err;
	// card number
	if (key->card_number) err = jsonify_key_string("card_number", key->card_number, dh, 1);
	else err = jsonify_key_null("card_number", dh, 1);
	if (err) return err;
	// curve
	if (key->curve) err = jsonify_key_string("curve", key->curve, dh, 0);
	else err = jsonify_key_null("curve", dh, 0);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_sig_notation(gpgme_sig_notation_t note, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	err = jsonify_key_string("sig_notation", "not_implemented", dh, 0);
	if (err) return err;
	// TODO
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_tofu_info(gpgme_tofu_info_t info, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	err = jsonify_key_string("tofu_info", "not_implemented", dh, 0);
	if (err) return err;
	// TODO
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_key_sig(gpgme_key_sig_t sig, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// is revoked ?
	err = jsonify_key_bool("revoked", sig->revoked, dh, 1);
	if (err) return err;
	// is expired ?
	err = jsonify_key_bool("expired", sig->expired, dh, 1);
	if (err) return err;
	// is invalid ?
	err = jsonify_key_bool("invalid", sig->invalid, dh, 1);
	if (err) return err;
	// is exportable ?
	err = jsonify_key_bool("exportable", sig->exportable, dh, 1);
	if (err) return err;
	// trust depth
	err = jsonify_key_int("trust_depth", sig->trust_depth, dh, 1);
	if (err) return err;
	// trust value
	err = jsonify_key_int("trust_value", sig->trust_value, dh, 1);
	if (err) return err;
	// algo
	err = jsonify_key_string("pubkey_algo", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, 1);
	if (err) return err;
	// keyid
	err = jsonify_key_string("keyid", sig->keyid, dh, 1);
	if (err) return err;
	// timestamp
	err = jsonify_key_int("timestamp", sig->timestamp, dh, 1);
	if (err) return err;
	// expires
	err = jsonify_key_int("expires", sig->expires, dh, 1);
	if (err) return err;
	// trust scope
	if (sig->trust_scope) err = jsonify_key_string("trust_scope", sig->trust_scope, dh, 1);
	else err = jsonify_key_null("trust_scope", dh, 1);
	if (err) return err;
	// status
	err = jsonify_string("status", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_gpgme_error(sig->status, dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// sig class
	err = jsonify_key_int("sig_class", sig->sig_class, dh, 1);
	if (err) return err;
	// uid
	err = jsonify_key_string("uid", sig->uid, dh, 1);
	if (err) return err;
	// name
	if (strlen(sig->name)) err = jsonify_key_string("name", sig->name, dh, 1);
	else err = jsonify_key_null("name", dh, 1);
	if (err) return err;
	// comment
	if (strlen(sig->comment)) err = jsonify_key_string("comment", sig->comment, dh, 1);
	else err = jsonify_key_null("comment", dh, 1);
	if (err) return err;
	// email
	if (strlen(sig->email)) err = jsonify_key_string("email", sig->email, dh, 1);
	else err = jsonify_key_null("email", dh, 1);
	if (err) return err;
	// notations
	err = jsonify_string("notations", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_sig_notation_t note = sig->notations;
	while (note) {
		err = jsonify_gpgme_sig_notation(note, dh);
		if (err) return err;
		if (note->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		note = note->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_user_id(gpgme_user_id_t uid, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// revoked ?
	err = jsonify_key_bool("revoked", uid->revoked, dh, 1);
	if (err) return err;
	// invalid ?
	err = jsonify_key_bool("invalid", uid->invalid, dh, 1);
	if (err) return err;
	// validity
	err = jsonify_key_string("validity", gpgme_validity_string(uid->validity), dh, 1);
	if (err) return err;
	// uid
	err = jsonify_key_string("uid", uid->uid, dh, 1);
	if (err) return err;
	// name
	if (strlen(uid->name)) err = jsonify_key_string("name", uid->name, dh, 1);
	else err = jsonify_key_null("name", dh, 1);
	if (err) return err;
	// comment
	if (strlen(uid->comment)) err = jsonify_key_string("comment", uid->comment, dh, 1);
	else err = jsonify_key_null("comment", dh, 1);
	if (err) return err;
	// email
	if (strlen(uid->email)) err = jsonify_key_string("email", uid->email, dh, 1);
	else err = jsonify_key_null("email", dh, 1);
	if (err) return err;
	// address
	if (uid->address) err = jsonify_key_string("address", uid->address, dh, 1);
	else err = jsonify_key_null("address", dh, 1);
	if (err) return err;
	// TOFU info
	err = jsonify_string("tofu", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_tofu_info_t info = uid->tofu;
	while (info) {
		err = jsonify_gpgme_tofu_info(info, dh);
		if (err) return err;
		if (info->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		info = info->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// signatures
	err = jsonify_string("signatures", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_key_sig_t sig = uid->signatures;
	while (sig) {
		err = jsonify_gpgme_key_sig(sig, dh);
		if (err) return err;
		if (sig->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		sig = sig->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_key(gpgme_key_t key, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// revoked ?
	err = jsonify_key_bool("revoked", key->revoked, dh, 1);
	if (err) return err;
	// expired ?
	err = jsonify_key_bool("expired", key->expired, dh, 1);
	if (err) return err;
	// disabled ?
	err = jsonify_key_bool("disabled", key->disabled, dh, 1);
	if (err) return err;
	// invalid ?
	err = jsonify_key_bool("invalid", key->invalid, dh, 1);
	if (err) return err;
	// can encrypt ?
	err = jsonify_key_bool("can_encrypt", key->can_encrypt, dh, 1);
	if (err) return err;
	// can sign ?
	err = jsonify_key_bool("can_sign", key->can_sign, dh, 1);
	if (err) return err;
	// can certify ?
	err = jsonify_key_bool("can_certify", key->can_certify, dh, 1);
	if (err) return err;
	// can authenticate ?
	err = jsonify_key_bool("can_authenticate", key->can_authenticate, dh, 1);
	if (err) return err;
	// is qualified ?
	err = jsonify_key_bool("is_qualified", key->is_qualified, dh, 1);
	if (err) return err;
	// is secret ?
	err = jsonify_key_bool("secret", key->secret, dh, 1);
	if (err) return err;
	// protocol
	err = jsonify_key_string("protocol", gpgme_get_protocol_name(key->protocol), dh, 1);
	if (err) return err;
	// issuer serial
	if (key->protocol == GPGME_PROTOCOL_CMS) err = jsonify_key_string("issuer_serial", key->issuer_serial, dh, 1);
	else err = jsonify_key_null("issuer_serial", dh, 1);
	if (err) return err;
	// issuer name
	if (key->protocol == GPGME_PROTOCOL_CMS) err = jsonify_key_string("issuer_name", key->issuer_name, dh, 1);
	else err = jsonify_key_null("issuer_name", dh, 1);
	if (err) return err;
	// chain id
	if (key->protocol == GPGME_PROTOCOL_CMS) err = jsonify_key_string("chain_id", key->chain_id, dh, 1);
	else err = jsonify_key_null("chain_id", dh, 1);
	if (err) return err;
	// owner trust
	if (key->protocol == GPGME_PROTOCOL_OpenPGP) err = jsonify_key_string("owner_trust", gpgme_validity_string(key->owner_trust), dh, 1);
	else err = jsonify_key_null("owner_trust", dh, 1);
	if (err) return err;
	// fpr
	err = jsonify_key_string("fingerprint", key->fpr, dh, 1);
	if (err) return err;
	// subkeys
	err = jsonify_string("subkeys", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_subkey_t subkey = key->subkeys;
	while (subkey) {
		err = jsonify_gpgme_subkey(subkey, dh);
		if (err) return err;
		if (subkey->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		subkey = subkey->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// uids
	err = jsonify_string("uids", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_user_id_t uid = key->uids;
	while (uid) {
		err = jsonify_gpgme_user_id(uid, dh);
		if (err) return err;
		if (uid->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		uid = uid->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_engine_info(gpgme_engine_info_t engine, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// protocol
	err = jsonify_key_string("protocol", gpgme_get_protocol_name(engine->protocol), dh, 1);
	if (err) return err;
	// file name
	if (engine->file_name) err = jsonify_key_string("file_name", engine->file_name, dh, 1);
	else err = jsonify_key_null("file_name", dh, 1);
	if (err) return err;
	// home dir
	if (engine->home_dir) err = jsonify_key_string("home_dir", engine->home_dir, dh, 1);
	else err = jsonify_key_null("home_dir", dh, 1);
	if (err) return err;
	// version
	if (engine->version) err = jsonify_key_string("version", engine->version, dh, 1);
	else err = jsonify_key_null("version", dh, 1);
	if (err) return err;
	// minimum required version
	if (engine->req_version) err = jsonify_key_string("req_version", engine->req_version, dh, 0);
	else err = jsonify_key_null("req_version", dh, 0);
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_include_certs(int num, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// value
	err = jsonify_key_int("value", num, dh, 1);
	if (err) return err;
	if (num < -2) err = jsonify_key_string("description", "undefined", dh, 0);
	if (num == -2) err = jsonify_key_string("description", "all_except_the_root", dh, 0);
	if (num == -1) err = jsonify_key_string("description", "all_certificates", dh, 0);
	if (num == 0) err = jsonify_key_string("description", "no_certificates", dh, 0);
	if (num == 1) err = jsonify_key_string("description", "sender_only", dh, 0);
	if (num > 1) err = jsonify_key_string("description", "first_n_certificates", dh, 0);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_ctx(gpgme_ctx_t ctx, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// protocol
	err = jsonify_key_string("protocol", gpgme_get_protocol_name(gpgme_get_protocol(ctx)), dh, 1);
	if (err) return err;
	// is armored ?
	err = jsonify_key_bool("armor", gpgme_get_armor(ctx), dh, 1);
	if (err) return err;
	// is textmode ?
	err = jsonify_key_bool("textmode", gpgme_get_textmode(ctx), dh, 1);
	if (err) return err;
	// is offline ?
	err = jsonify_key_bool("offline", gpgme_get_offline(ctx), dh, 1);
	if (err) return err;
	// sender
	if (gpgme_get_sender(ctx)) err = jsonify_key_string("sender", gpgme_get_sender(ctx), dh, 1);
	else err = jsonify_key_null("sender", dh, 1);
	if (err) return err;
	// engines
	err = jsonify_string("engine_info", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_engine_info_t engine = gpgme_ctx_get_engine_info(ctx);
	while (engine) {
		err = jsonify_gpgme_engine_info(engine, dh);
		if (err) return err;
		if (engine->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		engine = engine->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// pinentry mode
	err = jsonify_key_string("pinentry_mode", gpgme_pinentry_mode_string(gpgme_get_pinentry_mode(ctx)), dh, 1);
	if (err) return err;
	// include certs
	err = jsonify_string("include_certs", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_include_certs(gpgme_get_include_certs(ctx), dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// ctx flag
	err = jsonify_string("ctx_flag", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	const char *ctx_flags[19] = {
		"redraw",
		"full-status",
		"raw-description",
		"export-session-key",
		"override-session-key",
		"auto-key-retrieve",
		"auto-key-import",
		"include-key-block",
		"request-origin",
		"no-symkey-cache",
		"ignore-mdc-error",
		"auto-key-locate",
		"trust-model",
		"extended-edit",
		"cert-expire",
		"key-origin",
		"import-filter",
		"no-auto-check-trustdb",
		NULL
	};
	int i = 0;
	int comma = 1;
	while(ctx_flags[i]) {
		if (!ctx_flags[i + 1]) comma = 0;
		if (gpgme_get_ctx_flag(ctx, ctx_flags[i])) err = jsonify_key_string(ctx_flags[i], gpgme_get_ctx_flag(ctx, ctx_flags[i]), dh, comma);
		else err = jsonify_key_null(ctx_flags[i], dh, comma);
		if (err) return err;
		i++;
	}
	err = jsonify_right_brace(dh);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}


gpgme_error_t jsonify_gpgme_data(gpgme_data_t data, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// file name
	if (gpgme_data_get_file_name(data)) err = jsonify_key_string("file_name", gpgme_data_get_file_name(data), dh, 1);
	else err = jsonify_key_null("file_name", dh, 1);
	if (err) return err;
	// encoding
	err = jsonify_key_string("encoding", gpgme_data_encoding_string(gpgme_data_get_encoding(data)), dh, 1);
	if (err) return err;
	// data type
	err = jsonify_key_string("data_type", gpgme_data_type_string(gpgme_data_identify(data, 0)), dh, 0);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_signature(gpgme_signature_t sig, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// fpr
	err = jsonify_key_string("fpr", sig->fpr, dh, 1);
	if (err) return err;
	// status
	err = jsonify_string("status", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_gpgme_error(sig->status, dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// notations
	err = jsonify_string("notations", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_sig_notation_t note = sig->notations;
	while (note) {
		err = jsonify_gpgme_sig_notation(note, dh);
		if (err) return err;
		if (note->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		note = note->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_comma(dh);
	// timestamp
	err = jsonify_key_int("timestamp", sig->timestamp, dh, 1);
	if (err) return err;
	// expires
	err = jsonify_key_int("exp_timestamp", sig->exp_timestamp, dh, 1);
	if (err) return err;
	// wrong key usage
	err = jsonify_key_bool("wrong_key_usage", sig->wrong_key_usage, dh, 1);
	if (err) return err;
	// PKA trust
	err = jsonify_key_string("pka_trust", pka_trust_string(sig->pka_trust), dh, 1);
	if (err) return err;
	// chain model
	err = jsonify_key_bool("chain_model", sig->chain_model, dh, 1);
	if (err) return err;
	// validity
	err = jsonify_key_string("validity", gpgme_validity_string(sig->validity), dh, 1);
	if (err) return err;
	// validity reason
	err = jsonify_string("validity_reason", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_gpgme_error(sig->validity_reason, dh);
	if (err) return err;
	err = jsonify_comma(dh);
	if (err) return err;
	// pk algo
	err = jsonify_key_string("pubkey_algo", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, 1);
	if (err) return err;
	// hash algo
	err = jsonify_key_string("hash_algo", gpgme_hash_algo_name(sig->hash_algo), dh, 1);
	if (err) return err;
	// pka address
	if (sig->pka_address) err = jsonify_key_string("pka_address", sig->pka_address, dh, 1);
	else err = jsonify_key_null("pka_address", dh, 1);
	if (err) return err;
	// key
	err = jsonify_string("key", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	if (sig->key) err = jsonify_gpgme_key(sig->key, dh);
	else err = jsonify_null(dh);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_verify_result(gpgme_verify_result_t result, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err) return err;
	// file name
	if (result->file_name) err = jsonify_key_string("file_name", result->file_name, dh, 1);
	else err = jsonify_key_null("file_name", dh, 1);
	if (err) return err;
	// is mime ?
	err = jsonify_key_bool("is_mime", result->is_mime, dh, 1);
	if (err) return err;
	// signatures
	err = jsonify_string("signatures", dh);
	if (err) return err;
	err = jsonify_colon(dh);
	if (err) return err;
	err = jsonify_left_square_bracket(dh);
	if (err) return err;
	gpgme_signature_t sig = result->signatures;
	while (sig) {
		err = jsonify_gpgme_signature(sig, dh);
		if (err) return err;
		if (sig->next) {
			err = jsonify_comma(dh);
			if (err) return err;
		}
		sig = sig->next;
	}
	err = jsonify_right_square_bracket(dh);
	if (err) return err;
	err = jsonify_right_brace(dh);
	if (err) return err;
	return GPG_ERR_NO_ERROR;
}
