#include "gpgme_json.h"

/* CONST TO STRINGS */

const char *gpgme_validity_string(gpgme_validity_t val) {
	const char *result = "-\0";
	switch (val) {
	case GPGME_VALIDITY_UNKNOWN:
		result = "unknown\0";
	case GPGME_VALIDITY_UNDEFINED:
		result = "undefined\0";
	case GPGME_VALIDITY_NEVER:
		result = "never\0";
	case GPGME_VALIDITY_MARGINAL:
		result = "marginal\0";
	case GPGME_VALIDITY_FULL:
		result = "full\0";
	case GPGME_VALIDITY_ULTIMATE:
		result = "ultimate\0";
	}
	return result;
}

const char *gpgme_pinentry_mode_string(gpgme_pinentry_mode_t val) {
	const char *result = "-\0";
	switch (val) {
	case GPGME_PINENTRY_MODE_DEFAULT:
		result = "default\0";
	case GPGME_PINENTRY_MODE_ASK:
		result = "ask\0";
	case GPGME_PINENTRY_MODE_CANCEL:
		result = "cancel\0";
	case GPGME_PINENTRY_MODE_ERROR:
		result = "error\0";
	case GPGME_PINENTRY_MODE_LOOPBACK:
		result = "loopback\0";
	}
	return result;
}

const char *gpgme_data_encoding_string(gpgme_data_encoding_t val) {
	const char *result = "-\0";
	switch (val) {
	case GPGME_DATA_ENCODING_NONE:
		result = "none\0";
	case GPGME_DATA_ENCODING_BINARY:
		result = "binary\0";
	case GPGME_DATA_ENCODING_BASE64:
		result = "base64\0";
	case GPGME_DATA_ENCODING_ARMOR:
		result = "armor\0";
	case GPGME_DATA_ENCODING_MIME:
		result = "mime\0";
	case GPGME_DATA_ENCODING_URL:
		result = "url\0";
	case GPGME_DATA_ENCODING_URL0:
		result = "url0\0";
	case GPGME_DATA_ENCODING_URLESC:
		result = "urlesc\0";
	}
	return result;
}

const char *gpgme_data_type_string(gpgme_data_type_t val) {
	const char *result = "-\0";
	switch (val) {
	case GPGME_DATA_TYPE_INVALID:
		result = "invalid\0";
	case GPGME_DATA_TYPE_UNKNOWN:
		result = "unknown\0";
	case GPGME_DATA_TYPE_PGP_SIGNED:
		result = "pgp_signed\0";
	case GPGME_DATA_TYPE_PGP_ENCRYPTED:
		result = "pgp_encrypted\0";
	case GPGME_DATA_TYPE_PGP_SIGNATURE:
		result = "pgp_signature\0";
	case GPGME_DATA_TYPE_PGP_OTHER:
		result = "pgp_other\0";
	case GPGME_DATA_TYPE_PGP_KEY:
		result = "pgp_key\0";
	case GPGME_DATA_TYPE_CMS_SIGNED:
		result = "cms_signed\0";
	case GPGME_DATA_TYPE_CMS_ENCRYPTED:
		result = "cms_encrypted\0";
	case GPGME_DATA_TYPE_CMS_OTHER:
		result = "cms_other\0";
	case GPGME_DATA_TYPE_X509_CERT:
		result = "x509_cert\0";
	case GPGME_DATA_TYPE_PKCS12:
		result = "pkcs12\0";
	}
	return result;
}

const char *pka_trust_string(unsigned int val) {
	const char *result = "-\0";
	switch (val) {
	case 0:
		result = "no_pka_info\0";
	case 1:
		result = "pka_verification_failed\0";
	case 2:
		result = "pke_verification_success\0";
	}
	return result;
}

/* JSONIFY STRUCTS */

gpgme_error_t jsonify_gpgme_error(gpgme_error_t error, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// code
	err = jsonify_key_int("code\0", error, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// desc
	err = jsonify_key_string("description\0", gpgme_strerror(error), dh, 0);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_subkey(gpgme_subkey_t key, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// revoked ?
	err = jsonify_key_bool("revoked\0", key->revoked, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// expired ?
	err = jsonify_key_bool("expired\0", key->expired, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// disabled ?
	err = jsonify_key_bool("disabled\0", key->disabled, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// invalid ?
	err = jsonify_key_bool("invalid\0", key->invalid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can encrypt ?
	err = jsonify_key_bool("can_encrypt\0", key->can_encrypt, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can sign ?
	err = jsonify_key_bool("can_sign\0", key->can_sign, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can certify ?
	err = jsonify_key_bool("can_certify\0", key->can_certify, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can authenticate ?
	err = jsonify_key_bool("can_authenticate\0", key->can_authenticate, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is qualified ?
	err = jsonify_key_bool("is_qualified\0", key->is_qualified, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is DE VS?
	err = jsonify_key_bool("is_de_vs\0", key->is_de_vs, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is secret ?
	err = jsonify_key_bool("secret\0", key->secret, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// algo
	err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(key->pubkey_algo), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// length
	err = jsonify_key_int("length\0", key->length, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// keyid
	err = jsonify_key_string("keyid\0", key->keyid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// fpr
	err = jsonify_key_string("fingerprint\0", key->fpr, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// keygrip
	if (key->keygrip != NULL) {
		err = jsonify_key_string("keygrip\0", key->keygrip, dh, 1);
	} else {
		err = jsonify_key_null("keygrip\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// timestamp
	err = jsonify_key_int("timestamp\0", key->timestamp, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// expires
	err = jsonify_key_int("expires\0", key->expires, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is cardkey ?
	err = jsonify_key_bool("is_cardkey\0", key->is_cardkey, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// card number
	if (key->card_number != NULL) {
		err = jsonify_key_string("card_number\0", key->card_number, dh, 1);
	} else {
		err = jsonify_key_null("card_number\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// curve
	if (key->curve != NULL) {
		err = jsonify_key_string("curve\0", key->curve, dh, 0);
	} else {
		err = jsonify_key_null("curve\0", dh, 0);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_sig_notation(gpgme_sig_notation_t note, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_key_string("sig_notation\0", "not_implemented\0", dh, 0);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// TODO
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_tofu_info(gpgme_tofu_info_t info, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_key_string("tofu_info\0", "not_implemented\0", dh, 0);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// TODO
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_key_sig(gpgme_key_sig_t sig, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is revoked ?
	err = jsonify_key_bool("revoked\0", sig->revoked, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is expired ?
	err = jsonify_key_bool("expired\0", sig->expired, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is invalid ?
	err = jsonify_key_bool("invalid\0", sig->invalid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is exportable ?
	err = jsonify_key_bool("exportable\0", sig->exportable, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// trust depth
	err = jsonify_key_int("trust_depth\0", sig->trust_depth, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// trust value
	err = jsonify_key_int("trust_value\0", sig->trust_value, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// algo
	err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// keyid
	err = jsonify_key_string("keyid\0", sig->keyid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// timestamp
	err = jsonify_key_int("timestamp\0", sig->timestamp, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// expires
	err = jsonify_key_int("expires\0", sig->expires, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// trust scope
	if (sig->trust_scope != NULL) {
		err = jsonify_key_string("trust_scope\0", sig->trust_scope, dh, 1);
	} else {
		err = jsonify_key_null("trust_scope\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// status
	err = jsonify_string("status\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_gpgme_error(sig->status, dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// sig class
	err = jsonify_key_int("sig_class\0", sig->sig_class, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// uid
	err = jsonify_key_string("uid\0", sig->uid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// name
	if (strlen(sig->name)) {
		err = jsonify_key_string("name\0", sig->name, dh, 1);
	} else {
		err = jsonify_key_null("name\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// comment
	if (strlen(sig->comment)) {
		err = jsonify_key_string("comment\0", sig->comment, dh, 1);
	} else {
		err = jsonify_key_null("comment\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// email
	if (strlen(sig->email)) {
		err = jsonify_key_string("email\0", sig->email, dh, 1);
	} else {
		err = jsonify_key_null("email\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// notations
	err = jsonify_string("notations\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_sig_notation_t note = sig->notations;
	while (note) {
		err = jsonify_gpgme_sig_notation(note, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (note->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		note = note->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_user_id(gpgme_user_id_t uid, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// revoked ?
	err = jsonify_key_bool("revoked\0", uid->revoked, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// invalid ?
	err = jsonify_key_bool("invalid\0", uid->invalid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// validity
	err = jsonify_key_string("validity\0", gpgme_validity_string(uid->validity), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// uid
	err = jsonify_key_string("uid\0", uid->uid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// name
	if (strlen(uid->name)) {
		err = jsonify_key_string("name\0", uid->name, dh, 1);
	} else {
		err = jsonify_key_null("name\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// comment
	if (strlen(uid->comment)) {
		err = jsonify_key_string("comment\0", uid->comment, dh, 1);
	} else {
		err = jsonify_key_null("comment\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// email
	if (strlen(uid->email)) {
		err = jsonify_key_string("email\0", uid->email, dh, 1);
	} else {
		err = jsonify_key_null("email\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// address
	if (uid->address != NULL) {
		err = jsonify_key_string("address\0", uid->address, dh, 1);
	} else {
		err = jsonify_key_null("address\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// TOFU info
	err = jsonify_string("tofu\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_tofu_info_t info = uid->tofu;
	while (info) {
		err = jsonify_gpgme_tofu_info(info, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (info->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		info = info->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// signatures
	err = jsonify_string("signatures\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_key_sig_t sig = uid->signatures;
	while (sig) {
		err = jsonify_gpgme_key_sig(sig, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (sig->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		sig = sig->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_key(gpgme_key_t key, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// revoked ?
	err = jsonify_key_bool("revoked\0", key->revoked, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// expired ?
	err = jsonify_key_bool("expired\0", key->expired, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// disabled ?
	err = jsonify_key_bool("disabled\0", key->disabled, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// invalid ?
	err = jsonify_key_bool("invalid\0", key->invalid, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can encrypt ?
	err = jsonify_key_bool("can_encrypt\0", key->can_encrypt, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can sign ?
	err = jsonify_key_bool("can_sign\0", key->can_sign, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can certify ?
	err = jsonify_key_bool("can_certify\0", key->can_certify, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// can authenticate ?
	err = jsonify_key_bool("can_authenticate\0", key->can_authenticate, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is qualified ?
	err = jsonify_key_bool("is_qualified\0", key->is_qualified, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is secret ?
	err = jsonify_key_bool("secret\0", key->secret, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// protocol
	err = jsonify_key_string("protocol\0", gpgme_get_protocol_name(key->protocol), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// issuer serial
	if (key->protocol == GPGME_PROTOCOL_CMS) {
		err = jsonify_key_string("issuer_serial\0", key->issuer_serial, dh, 1);
	} else {
		err = jsonify_key_null("issuer_serial\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// issuer name
	if (key->protocol == GPGME_PROTOCOL_CMS) {
		err = jsonify_key_string("issuer_name\0", key->issuer_name, dh, 1);
	} else {
		err = jsonify_key_null("issuer_name\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// chain id
	if (key->protocol == GPGME_PROTOCOL_CMS) {
		err = jsonify_key_string("chain_id\0", key->chain_id, dh, 1);
	} else {
		err = jsonify_key_null("chain_id\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// owner trust
	if (key->protocol == GPGME_PROTOCOL_OpenPGP) {
		err = jsonify_key_string("owner_trust\0", gpgme_validity_string(key->owner_trust), dh, 1);
	} else {
		err = jsonify_key_null("owner_trust\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// fpr
	err = jsonify_key_string("fingerprint\0", key->fpr, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// subkeys
	err = jsonify_string("subkeys\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_subkey_t subkey = key->subkeys;
	while (subkey) {
		err = jsonify_gpgme_subkey(subkey, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (subkey->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		subkey = subkey->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// uids
	err = jsonify_string("uids\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_user_id_t uid = key->uids;
	while (uid) {
		err = jsonify_gpgme_user_id(uid, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (uid->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		uid = uid->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_engine_info(gpgme_engine_info_t engine, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// protocol
	err = jsonify_key_string("protocol\0", gpgme_get_protocol_name(engine->protocol), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// file name
	if (engine->file_name != NULL) {
		err = jsonify_key_string("file_name\0", engine->file_name, dh, 1);
	} else {
		err = jsonify_key_null("file_name\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// home dir
	if (engine->home_dir != NULL) {
		err = jsonify_key_string("home_dir\0", engine->home_dir, dh, 1);
	} else {
		err = jsonify_key_null("home_dir\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// version
	if (engine->version != NULL) {
		err = jsonify_key_string("version\0", engine->version, dh, 1);
	} else {
		err = jsonify_key_null("version\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// minimum required version
	if (engine->req_version != NULL) {
		err = jsonify_key_string("req_version\0", engine->req_version, dh, 0);
	} else {
		err = jsonify_key_null("req_version\0", dh, 0);
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_include_certs(int num, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// value
	err = jsonify_key_int("value\0", num, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	if (num < -2) {
		err = jsonify_key_string("description\0", "undefined\0", dh, 0);
	}
	if (num == -2) {
		err = jsonify_key_string("description\0", "all_except_the_root\0", dh, 0);
	}
	if (num == -1) {
		err = jsonify_key_string("description\0", "all_certificates\0", dh, 0);
	}
	if (num == 0) {
		err = jsonify_key_string("description\0", "no_certificates\0", dh, 0);
	}
	if (num == 1) {
		err = jsonify_key_string("description\0", "sender_only\0", dh, 0);
	}
	if (num > 1) {
		err = jsonify_key_string("description\0", "first_n_certificates\0", dh, 0);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_ctx(gpgme_ctx_t ctx, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// protocol
	err = jsonify_key_string("protocol\0", gpgme_get_protocol_name(gpgme_get_protocol(ctx)), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is armored ?
	err = jsonify_key_bool("armor\0", gpgme_get_armor(ctx), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is textmode ?
	err = jsonify_key_bool("textmode\0", gpgme_get_textmode(ctx), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is offline ?
	err = jsonify_key_bool("offline\0", gpgme_get_offline(ctx), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// sender
	if (gpgme_get_sender(ctx) != NULL) {
		err = jsonify_key_string("sender\0", gpgme_get_sender(ctx), dh, 1);
	} else {
		err = jsonify_key_null("sender\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// engines
	err = jsonify_string("engine_info\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_engine_info_t engine = gpgme_ctx_get_engine_info(ctx);
	while (engine) {
		err = jsonify_gpgme_engine_info(engine, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (engine->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		engine = engine->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// pinentry mode
	err = jsonify_key_string("pinentry_mode\0", gpgme_pinentry_mode_string(gpgme_get_pinentry_mode(ctx)), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// include certs
	err = jsonify_string("include_certs\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_include_certs(gpgme_get_include_certs(ctx), dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// ctx flag
	err = jsonify_string("ctx_flag\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	const char *ctx_flags[19] = {
		"redraw\0",
		"full-status\0",
		"raw-description\0",
		"export-session-key\0",
		"override-session-key\0",
		"auto-key-retrieve\0",
		"auto-key-import\0",
		"include-key-block\0",
		"request-origin\0",
		"no-symkey-cache\0",
		"ignore-mdc-error\0",
		"auto-key-locate\0",
		"trust-model\0",
		"extended-edit\0",
		"cert-expire\0",
		"key-origin\0",
		"import-filter\0",
		"no-auto-check-trustdb\0",
		NULL
	};
	int i = 0;
	int comma = 1;
	while (ctx_flags[i]) {
		if (!ctx_flags[i + 1]) comma = 0;
		if (gpgme_get_ctx_flag(ctx, ctx_flags[i]) != NULL) {
			err = jsonify_key_string(ctx_flags[i], gpgme_get_ctx_flag(ctx, ctx_flags[i]), dh, comma);
		} else {
			err = jsonify_key_null(ctx_flags[i], dh, comma);
		}
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		i++;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_data(gpgme_data_t data, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// file name
	if (gpgme_data_get_file_name(data) != NULL) {
		err = jsonify_key_string("file_name\0", gpgme_data_get_file_name(data), dh, 1);
	} else {
		err = jsonify_key_null("file_name\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// encoding
	err = jsonify_key_string("encoding\0", gpgme_data_encoding_string(gpgme_data_get_encoding(data)), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// data type
	err = jsonify_key_string("data_type\0", gpgme_data_type_string(gpgme_data_identify(data, 0)), dh, 0);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_signature(gpgme_signature_t sig, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// fpr
	err = jsonify_key_string("fpr\0", sig->fpr, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// status
	err = jsonify_string("status\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_gpgme_error(sig->status, dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// notations
	err = jsonify_string("notations\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_sig_notation_t note = sig->notations;
	while (note) {
		err = jsonify_gpgme_sig_notation(note, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (note->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		note = note->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	// timestamp
	err = jsonify_key_int("timestamp\0", sig->timestamp, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// expires
	err = jsonify_key_int("exp_timestamp\0", sig->exp_timestamp, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// wrong key usage
	err = jsonify_key_bool("wrong_key_usage\0", sig->wrong_key_usage, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// PKA trust
	err = jsonify_key_string("pka_trust\0", pka_trust_string(sig->pka_trust), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// chain model
	err = jsonify_key_bool("chain_model\0", sig->chain_model, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// validity
	err = jsonify_key_string("validity\0", gpgme_validity_string(sig->validity), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// validity reason
	err = jsonify_string("validity_reason\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_gpgme_error(sig->validity_reason, dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_comma(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// pk algo
	err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// hash algo
	err = jsonify_key_string("hash_algo\0", gpgme_hash_algo_name(sig->hash_algo), dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// pka address
	if (sig->pka_address != NULL) {
		err = jsonify_key_string("pka_address\0", sig->pka_address, dh, 1);
	} else {
		err = jsonify_key_null("pka_address\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// key
	err = jsonify_string("key\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	if (sig->key != NULL) {
		err = jsonify_gpgme_key(sig->key, dh);
	} else {
		err = jsonify_null(dh);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}

gpgme_error_t jsonify_gpgme_verify_result(gpgme_verify_result_t result, gpgme_data_t dh) {
	gpgme_error_t err;
	err = jsonify_left_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// file name
	if (result->file_name != NULL) {
		err = jsonify_key_string("file_name\0", result->file_name, dh, 1);
	} else {
		err = jsonify_key_null("file_name\0", dh, 1);
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// is mime ?
	err = jsonify_key_bool("is_mime\0", result->is_mime, dh, 1);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	// signatures
	err = jsonify_string("signatures\0", dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_colon(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_left_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	gpgme_signature_t sig = result->signatures;
	while (sig) {
		err = jsonify_gpgme_signature(sig, dh);
		if (err != GPG_ERR_NO_ERROR) {
			break;
		}
		if (sig->next) {
			err = jsonify_comma(dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
		}
		sig = sig->next;
	}
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_square_bracket(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	err = jsonify_right_brace(dh);
	if (err != GPG_ERR_NO_ERROR) {
		return err;
	}
	return GPG_ERR_NO_ERROR;
}
