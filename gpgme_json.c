#include "gpgme_json.h"

size_t string_length(char *str) {
	return strlen(str);
}

/* CONST TO STRINGS */

const char *gpgme_validity_string(gpgme_validity_t val) {
	const char *result;
	switch (val) {
	case GPGME_VALIDITY_UNKNOWN:
		result = "unknown\0";
		break;
	case GPGME_VALIDITY_UNDEFINED:
		result = "undefined\0";
		break;
	case GPGME_VALIDITY_NEVER:
		result = "never\0";
		break;
	case GPGME_VALIDITY_MARGINAL:
		result = "marginal\0";
		break;
	case GPGME_VALIDITY_FULL:
		result = "full\0";
		break;
	case GPGME_VALIDITY_ULTIMATE:
		result = "ultimate\0";
		break;
	default:
		result = "-\0";
		break;
	}
	return result;
}

const char *gpgme_pinentry_mode_string(gpgme_pinentry_mode_t val) {
	const char *result;
	switch (val) {
	case GPGME_PINENTRY_MODE_DEFAULT:
		result = "default\0";
		break;
	case GPGME_PINENTRY_MODE_ASK:
		result = "ask\0";
		break;
	case GPGME_PINENTRY_MODE_CANCEL:
		result = "cancel\0";
		break;
	case GPGME_PINENTRY_MODE_ERROR:
		result = "error\0";
		break;
	case GPGME_PINENTRY_MODE_LOOPBACK:
		result = "loopback\0";
		break;
	default:
		result = "-\0";
		break;
	}
	return result;
}

const char *gpgme_data_encoding_string(gpgme_data_encoding_t val) {
	const char *result;
	switch (val) {
	case GPGME_DATA_ENCODING_NONE:
		result = "none\0";
		break;
	case GPGME_DATA_ENCODING_BINARY:
		result = "binary\0";
		break;
	case GPGME_DATA_ENCODING_BASE64:
		result = "base64\0";
		break;
	case GPGME_DATA_ENCODING_ARMOR:
		result = "armor\0";
		break;
	case GPGME_DATA_ENCODING_MIME:
		result = "mime\0";
		break;
	case GPGME_DATA_ENCODING_URL:
		result = "url\0";
		break;
	case GPGME_DATA_ENCODING_URL0:
		result = "url0\0";
		break;
	case GPGME_DATA_ENCODING_URLESC:
		result = "urlesc\0";
		break;
	default:
		result = "-\0";
		break;
	}
	return result;
}

const char *gpgme_data_type_string(gpgme_data_type_t val) {
	const char *result;
	switch (val) {
	case GPGME_DATA_TYPE_INVALID:
		result = "invalid\0";
		break;
	case GPGME_DATA_TYPE_UNKNOWN:
		result = "unknown\0";
		break;
	case GPGME_DATA_TYPE_PGP_SIGNED:
		result = "pgp_signed\0";
		break;
	case GPGME_DATA_TYPE_PGP_ENCRYPTED:
		result = "pgp_encrypted\0";
		break;
	case GPGME_DATA_TYPE_PGP_SIGNATURE:
		result = "pgp_signature\0";
		break;
	case GPGME_DATA_TYPE_PGP_OTHER:
		result = "pgp_other\0";
		break;
	case GPGME_DATA_TYPE_PGP_KEY:
		result = "pgp_key\0";
		break;
	case GPGME_DATA_TYPE_CMS_SIGNED:
		result = "cms_signed\0";
		break;
	case GPGME_DATA_TYPE_CMS_ENCRYPTED:
		result = "cms_encrypted\0";
		break;
	case GPGME_DATA_TYPE_CMS_OTHER:
		result = "cms_other\0";
		break;
	case GPGME_DATA_TYPE_X509_CERT:
		result = "x509_cert\0";
		break;
	case GPGME_DATA_TYPE_PKCS12:
		result = "pkcs12\0";
		break;
	default:
		result = "-\0";
		break;
	}
	return result;
}

const char *pka_trust_string(unsigned int val) {
	const char *result;
	switch (val) {
	case 0:
		result = "no_pka_info\0";
		break;
	case 1:
		result = "pka_verification_failed\0";
		break;
	case 2:
		result = "pke_verification_success\0";
		break;
	default:
		result = "-\0";
		break;
	}
	return result;
}

const char *gpgme_sig_mode_string(gpgme_sig_mode_t val) {
	const char *result;
	switch (val) {
	case GPGME_SIG_MODE_NORMAL:
		result = "normal\0";
		break;
	case GPGME_SIG_MODE_DETACH:
		result = "detach\0";
		break;
	case GPGME_SIG_MODE_CLEAR:
		result = "clear\0";
		break;
	default:
		result = "-\0";
		break;
	}
	return result;
}

/* JSONIFY STRUCTS */

gpgme_error_t jsonify_gpgme_error(gpgme_error_t error, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// code
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("code\0", error, dh, true);
	}
	// desc
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("description\0", gpgme_strerror(error), dh, false);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_subkey(gpgme_subkey_t key, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// revoked ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("revoked\0", key->revoked, dh, true);
	}
	// expired ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("expired\0", key->expired, dh, true);
	}
	// disabled ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("disabled\0", key->disabled, dh, true);
	}
	// invalid ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("invalid\0", key->invalid, dh, true);
	}
	// can encrypt ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_encrypt\0", key->can_encrypt, dh, true);
	}
	// can sign ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_sign\0", key->can_sign, dh, true);
	}
	// can certify ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_certify\0", key->can_certify, dh, true);
	}
	// can authenticate ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_authenticate\0", key->can_authenticate, dh, true);
	}
	// is qualified ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_qualified\0", key->is_qualified, dh, true);
	}
	// is DE VS?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_de_vs\0", key->is_de_vs, dh, true);
	}
	// is secret ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("secret\0", key->secret, dh, true);
	}
	// algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(key->pubkey_algo), dh, true);
	}
	// length
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("length\0", key->length, dh, true);
	}
	// keyid
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("keyid\0", key->keyid, dh, true);
	}
	// fpr
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("fingerprint\0", key->fpr, dh, true);
	}
	// keygrip
	if (err == GPG_ERR_NO_ERROR) {
		if (key->keygrip != NULL) {
			err = jsonify_key_string("keygrip\0", key->keygrip, dh, true);
		} else {
			err = jsonify_key_null("keygrip\0", dh, true);
		}
	}
	// timestamp
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("timestamp\0", key->timestamp, dh, true);
	}
	// expires
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("expires\0", key->expires, dh, true);
	}
	// is cardkey ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_cardkey\0", key->is_cardkey, dh, true);
	}
	// card number
	if (err == GPG_ERR_NO_ERROR) {
		if (key->card_number != NULL) {
			err = jsonify_key_string("card_number\0", key->card_number, dh, true);
		} else {
			err = jsonify_key_null("card_number\0", dh, true);
		}
	}
	// curve
	if (err == GPG_ERR_NO_ERROR) {
		if (key->curve != NULL) {
			err = jsonify_key_string("curve\0", key->curve, dh, false);
		} else {
			err = jsonify_key_null("curve\0", dh, false);
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_sig_notation(gpgme_sig_notation_t note, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("sig_notation\0", "not_implemented\0", dh, false);
	}
	// TODO
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_tofu_info(gpgme_tofu_info_t info, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("tofu_info\0", "not_implemented\0", dh, false);
	}
	// TODO
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_key_sig(gpgme_key_sig_t sig, gpgme_data_t dh) {
	size_t zero = 0;
	gpgme_error_t err = jsonify_left_brace(dh);
	// is revoked ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("revoked\0", sig->revoked, dh, true);
	}
	// is expired ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("expired\0", sig->expired, dh, true);
	}
	// is invalid ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("invalid\0", sig->invalid, dh, true);
	}
	// is exportable ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("exportable\0", sig->exportable, dh, true);
	}
	// trust depth
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("trust_depth\0", sig->trust_depth, dh, true);
	}
	// trust value
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("trust_value\0", sig->trust_value, dh, true);
	}
	// algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, true);
	}
	// keyid
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("keyid\0", sig->keyid, dh, true);
	}
	// timestamp
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("timestamp\0", sig->timestamp, dh, true);
	}
	// expires
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("expires\0", sig->expires, dh, true);
	}
	// trust scope
	if (err == GPG_ERR_NO_ERROR) {
		if (sig->trust_scope != NULL) {
			err = jsonify_key_string("trust_scope\0", sig->trust_scope, dh, true);
		} else {
			err = jsonify_key_null("trust_scope\0", dh, true);
		}
	}
	// status
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("status\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_error(sig->status, dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// sig class
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("sig_class\0", sig->sig_class, dh, true);
	}
	// uid
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("uid\0", sig->uid, dh, true);
	}
	// name
	if (err == GPG_ERR_NO_ERROR) {
		if (string_length(sig->name) != zero) {
			err = jsonify_key_string("name\0", sig->name, dh, true);
		} else {
			err = jsonify_key_null("name\0", dh, true);
		}
	}
	// comment
	if (err == GPG_ERR_NO_ERROR) {
		if (string_length(sig->comment) != zero) {
			err = jsonify_key_string("comment\0", sig->comment, dh, true);
		} else {
			err = jsonify_key_null("comment\0", dh, true);
		}
	}
	// email
	if (err == GPG_ERR_NO_ERROR) {
		if (string_length(sig->email) != zero) {
			err = jsonify_key_string("email\0", sig->email, dh, true);
		} else {
			err = jsonify_key_null("email\0", dh, true);
		}
	}
	// notations
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("notations\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_sig_notation_t note = sig->notations;
		while (note != NULL) {
			err = jsonify_gpgme_sig_notation(note, dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
			if (note->next != NULL) {
				err = jsonify_comma(dh);
				if (err != GPG_ERR_NO_ERROR) {
					break;
				}
			}
			note = note->next;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_user_id(gpgme_user_id_t uid, gpgme_data_t dh) {
	size_t zero = 0;
	gpgme_error_t err = jsonify_left_brace(dh);
	// revoked ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("revoked\0", uid->revoked, dh, true);
	}
	// invalid ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("invalid\0", uid->invalid, dh, true);
	}
	// validity
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("validity\0", gpgme_validity_string(uid->validity), dh, true);
	}
	// uid
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("uid\0", uid->uid, dh, true);
	}
	// name
	if (err == GPG_ERR_NO_ERROR) {
		if (string_length(uid->name) != zero) {
			err = jsonify_key_string("name\0", uid->name, dh, true);
		} else {
			err = jsonify_key_null("name\0", dh, true);
		}
	}
	// comment
	if (err == GPG_ERR_NO_ERROR) {
		if (string_length(uid->comment) != zero) {
			err = jsonify_key_string("comment\0", uid->comment, dh, true);
		} else {
			err = jsonify_key_null("comment\0", dh, true);
		}
	}
	// email
	if (err == GPG_ERR_NO_ERROR) {
		if (string_length(uid->email) != zero) {
			err = jsonify_key_string("email\0", uid->email, dh, true);
		} else {
			err = jsonify_key_null("email\0", dh, true);
		}
	}
	// address
	if (err == GPG_ERR_NO_ERROR) {
		if (uid->address != NULL) {
			err = jsonify_key_string("address\0", uid->address, dh, true);
		} else {
			err = jsonify_key_null("address\0", dh, true);
		}
	}
	// TOFU info
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("tofu\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// signatures
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("signatures\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_key(gpgme_key_t key, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// revoked ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("revoked\0", key->revoked, dh, true);
	}
	// expired ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("expired\0", key->expired, dh, true);
	}
	// disabled ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("disabled\0", key->disabled, dh, true);
	}
	// invalid ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("invalid\0", key->invalid, dh, true);
	}
	// can encrypt ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_encrypt\0", key->can_encrypt, dh, true);
	}
	// can sign ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_sign\0", key->can_sign, dh, true);
	}
	// can certify ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_certify\0", key->can_certify, dh, true);
	}
	// can authenticate ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("can_authenticate\0", key->can_authenticate, dh, true);
	}
	// is qualified ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_qualified\0", key->is_qualified, dh, true);
	}
	// is secret ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("secret\0", key->secret, dh, true);
	}
	// protocol
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("protocol\0", gpgme_get_protocol_name(key->protocol), dh, true);
	}
	// issuer serial
	if (err == GPG_ERR_NO_ERROR) {
		if (key->protocol == GPGME_PROTOCOL_CMS) {
			err = jsonify_key_string("issuer_serial\0", key->issuer_serial, dh, true);
		} else {
			err = jsonify_key_null("issuer_serial\0", dh, true);
		}
	}
	// issuer name
	if (err == GPG_ERR_NO_ERROR) {
		if (key->protocol == GPGME_PROTOCOL_CMS) {
			err = jsonify_key_string("issuer_name\0", key->issuer_name, dh, true);
		} else {
			err = jsonify_key_null("issuer_name\0", dh, true);
		}
	}
	// chain id
	if (err == GPG_ERR_NO_ERROR) {
		if (key->protocol == GPGME_PROTOCOL_CMS) {
			err = jsonify_key_string("chain_id\0", key->chain_id, dh, true);
		} else {
			err = jsonify_key_null("chain_id\0", dh, true);
		}
	}
	// owner trust
	if (err == GPG_ERR_NO_ERROR) {
		if (key->protocol == GPGME_PROTOCOL_OpenPGP) {
			err = jsonify_key_string("owner_trust\0", gpgme_validity_string(key->owner_trust), dh, true);
		} else {
			err = jsonify_key_null("owner_trust\0", dh, true);
		}
	}
	// fpr
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("fingerprint\0", key->fpr, dh, true);
	}
	// subkeys
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("subkeys\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// uids
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("uids\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_engine_info(gpgme_engine_info_t engine, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// protocol
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("protocol\0", gpgme_get_protocol_name(engine->protocol), dh, true);
	}
	// file name
	if (err == GPG_ERR_NO_ERROR) {
		if (engine->file_name != NULL) {
			err = jsonify_key_string("file_name\0", engine->file_name, dh, true);
		} else {
			err = jsonify_key_null("file_name\0", dh, true);
		}
	}
	// home dir
	if (err == GPG_ERR_NO_ERROR) {
		if (engine->home_dir != NULL) {
			err = jsonify_key_string("home_dir\0", engine->home_dir, dh, true);
		} else {
			err = jsonify_key_null("home_dir\0", dh, true);
		}
	}
	// version
	if (err == GPG_ERR_NO_ERROR) {
		if (engine->version != NULL) {
			err = jsonify_key_string("version\0", engine->version, dh, true);
		} else {
			err = jsonify_key_null("version\0", dh, true);
		}
	}
	// minimum required version
	if (err == GPG_ERR_NO_ERROR) {
		if (engine->req_version != NULL) {
			err = jsonify_key_string("req_version\0", engine->req_version, dh, false);
		} else {
			err = jsonify_key_null("req_version\0", dh, false);
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_include_certs(int num, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// value
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("value\0", num, dh, true);
	}
	if (err == GPG_ERR_NO_ERROR) {
		if (num < -2) {
			err = jsonify_key_string("description\0", "undefined\0", dh, false);
		} else if (num == -2) {
			err = jsonify_key_string("description\0", "all_except_the_root\0", dh, false);
		} else if (num == -1) {
			err = jsonify_key_string("description\0", "all_certificates\0", dh, false);
		} else if (num == 0) {
			err = jsonify_key_string("description\0", "no_certificates\0", dh, false);
		} else if (num == 1) {
			err = jsonify_key_string("description\0", "sender_only\0", dh, false);
		} else {
			err = jsonify_key_string("description\0", "first_n_certificates\0", dh, false);
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_ctx(gpgme_ctx_t ctx, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// protocol
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("protocol\0", gpgme_get_protocol_name(gpgme_get_protocol(ctx)), dh, true);
	}
	// is armored ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("armor\0", gpgme_get_armor(ctx), dh, true);
	}
	// is textmode ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("textmode\0", gpgme_get_textmode(ctx), dh, true);
	}
	// is offline ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("offline\0", gpgme_get_offline(ctx), dh, true);
	}
	// sender
	if (err == GPG_ERR_NO_ERROR) {
		if (gpgme_get_sender(ctx) != NULL) {
			err = jsonify_key_string("sender\0", gpgme_get_sender(ctx), dh, true);
		} else {
			err = jsonify_key_null("sender\0", dh, true);
		}
	}
	// engines
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("engine_info\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// pinentry mode
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pinentry_mode\0", gpgme_pinentry_mode_string(gpgme_get_pinentry_mode(ctx)), dh, true);
	}
	// include certs
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("include_certs\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_include_certs(gpgme_get_include_certs(ctx), dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// ctx flag
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("ctx_flag\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_brace(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
		while (ctx_flags[i] != NULL) {
			if (ctx_flags[i + 1] == NULL) {
				comma = 0;
			}
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_data(gpgme_data_t data, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// file name
	if (err == GPG_ERR_NO_ERROR) {
		if (gpgme_data_get_file_name(data) != NULL) {
			err = jsonify_key_string("file_name\0", gpgme_data_get_file_name(data), dh, true);
		} else {
			err = jsonify_key_null("file_name\0", dh, true);
		}
	}
	// encoding
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("encoding\0", gpgme_data_encoding_string(gpgme_data_get_encoding(data)), dh, true);
	}
	// data type
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("data_type\0", gpgme_data_type_string(gpgme_data_identify(data, 0)), dh, false);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_signature(gpgme_signature_t sig, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// fpr
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("fpr\0", sig->fpr, dh, true);
	}
	// status
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("status\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_error(sig->status, dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// notations
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("notations\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// timestamp
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("timestamp\0", sig->timestamp, dh, true);
	}
	// expires
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("exp_timestamp\0", sig->exp_timestamp, dh, true);
	}
	// wrong key usage
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("wrong_key_usage\0", sig->wrong_key_usage, dh, true);
	}
	// PKA trust
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pka_trust\0", pka_trust_string(sig->pka_trust), dh, true);
	}
	// chain model
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("chain_model\0", sig->chain_model, dh, true);
	}
	// validity
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("validity\0", gpgme_validity_string(sig->validity), dh, true);
	}
	// validity reason
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("validity_reason\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_error(sig->validity_reason, dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// pk algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, true);
	}
	// hash algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("hash_algo\0", gpgme_hash_algo_name(sig->hash_algo), dh, true);
	}
	// pka address
	if (err == GPG_ERR_NO_ERROR) {
		if (sig->pka_address != NULL) {
			err = jsonify_key_string("pka_address\0", sig->pka_address, dh, true);
		} else {
			err = jsonify_key_null("pka_address\0", dh, true);
		}
	}
	// key
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("key\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		if (sig->key != NULL) {
			err = jsonify_gpgme_key(sig->key, dh);
		} else {
			err = jsonify_null(dh);
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_verify_result(gpgme_verify_result_t result, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// file name
	if (err == GPG_ERR_NO_ERROR) {
		if (result->file_name != NULL) {
			err = jsonify_key_string("file_name\0", result->file_name, dh, true);
		} else {
			err = jsonify_key_null("file_name\0", dh, true);
		}
	}
	// is mime ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_mime\0", result->is_mime, dh, true);
	}
	// signatures
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("signatures\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_signature_t sig = result->signatures;
		while (sig) {
			err = jsonify_gpgme_signature(sig, dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
			if (sig->next != NULL) {
				err = jsonify_comma(dh);
				if (err != GPG_ERR_NO_ERROR) {
					break;
				}
			}
			sig = sig->next;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_invalid_key(gpgme_invalid_key_t key, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// fpr
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("fpr\0", key->fpr, dh, true);
	}
	// status
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("reason\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_error(key->reason, dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_new_signature(gpgme_new_signature_t sig, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// sig type
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("type\0", gpgme_sig_mode_string(sig->type), dh, true);
	}
	// pk algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(sig->pubkey_algo), dh, true);
	}
	// hash algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("hash_algo\0", gpgme_hash_algo_name(sig->hash_algo), dh, true);
	}
	// sig class
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("sig_class\0", sig->sig_class, dh, true);
	}
	// timestamp
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_int("timestamp\0", sig->timestamp, dh, true);
	}
	// fpr
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("fpr\0", sig->fpr, dh, false);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_sign_result(gpgme_sign_result_t result, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("invalid_signers\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_invalid_key_t siner = result->invalid_signers;
		while (siner != NULL) {
			err = jsonify_gpgme_invalid_key(siner, dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
			if (siner->next != NULL) {
				err = jsonify_comma(dh);
				if (err != GPG_ERR_NO_ERROR) {
					break;
				}
			}
			siner = siner->next;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// signatures
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("signatures\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_new_signature_t sig = result->signatures;
		while (sig != NULL) {
			err = jsonify_gpgme_new_signature(sig, dh);
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
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_encrypt_result(gpgme_encrypt_result_t result, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("invalid_recipients\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_invalid_key_t rec = result->invalid_recipients;
		while (rec != NULL) {
			err = jsonify_gpgme_invalid_key(rec, dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
			if (rec->next != 0) {
				err = jsonify_comma(dh);
				if (err != GPG_ERR_NO_ERROR) {
					break;
				}
			}
			rec = rec->next;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_recipient(gpgme_recipient_t rec, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("pubkey_algo\0", gpgme_pubkey_algo_name(rec->pubkey_algo), dh, true);
	}
	// keyid
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("keyid\0", rec->keyid, dh, true);
	}
	// status
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("status\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_gpgme_error(rec->status, dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}

gpgme_error_t jsonify_gpgme_decrypt_result(gpgme_decrypt_result_t result, gpgme_data_t dh) {
	gpgme_error_t err = jsonify_left_brace(dh);
	// unsupported algo
	if (err == GPG_ERR_NO_ERROR) {
		if (result->unsupported_algorithm != NULL) {
			err = jsonify_key_string("unsupported_algorithm\0", result->unsupported_algorithm, dh, true);
		} else {
			err = jsonify_key_null("unsupported_algorithm\0", dh, true);
		}
	}
	// wrong key usage
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("wrong_key_usage\0", result->wrong_key_usage, dh, true);
	}
	// legacy cipher nomdc
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("legacy_cipher_nomdc\0", result->legacy_cipher_nomdc, dh, true);
	}
	// is mime ?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_mime\0", result->is_mime, dh, true);
	}
	// is DE VS?
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_bool("is_de_vs\0", result->is_de_vs, dh, true);
	}
	// file name
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_string("recipients\0", dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_colon(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_left_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		gpgme_recipient_t rec = result->recipients;
		while (rec != NULL) {
			err = jsonify_gpgme_recipient(rec, dh);
			if (err != GPG_ERR_NO_ERROR) {
				break;
			}
			if (rec->next != NULL) {
				err = jsonify_comma(dh);
				if (err != GPG_ERR_NO_ERROR) {
					break;
				}
			}
			rec = rec->next;
		}
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_square_bracket(dh);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_comma(dh);
	}
	// file name
	if (err == GPG_ERR_NO_ERROR) {
		if (result->file_name != NULL) {
			err = jsonify_key_string("file_name\0", result->file_name, dh, true);
		} else {
			err = jsonify_key_null("file_name\0", dh, true);
		}
	}
	// TODO session key
	
	// symkey algo
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_key_string("symkey_algo\0", result->symkey_algo, dh, false);
	}
	if (err == GPG_ERR_NO_ERROR) {
		err = jsonify_right_brace(dh);
	}
	return err;
}
