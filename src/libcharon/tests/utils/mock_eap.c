/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "mock_eap.h"

#define REQUEST_MSG "password"
#define MOCK_PW_MSG "mock password"

typedef struct private_eap_method_t private_eap_method_t;

/**
 * Private data
 */
struct private_eap_method_t {

	/**
	 * Public interface
	 */
	eap_method_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * EAP message identifier
	 */
	uint8_t identifier;
};

typedef struct eap_gtc_header_t eap_gtc_header_t;

/**
 * packed eap GTC header struct
 */
struct eap_gtc_header_t {
	/** EAP code (REQUEST/RESPONSE) */
	uint8_t code;
	/** unique message identifier */
	uint8_t identifier;
	/** length of whole message */
	uint16_t length;
	/** EAP type */
	uint8_t type;
	/** type data */
	uint8_t data[];
} __attribute__((__packed__));

METHOD(eap_method_t, initiate_peer, status_t,
	private_eap_method_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

METHOD(eap_method_t, initiate_server, status_t,
	private_eap_method_t *this, eap_payload_t **out)
{
	eap_gtc_header_t *req;
	size_t len;

	len = strlen(REQUEST_MSG);
	req = alloca(sizeof(eap_gtc_header_t) + len);
	req->length = htons(sizeof(eap_gtc_header_t) + len);
	req->code = EAP_REQUEST;
	req->identifier = this->identifier;
	req->type = EAP_GTC;
	memcpy(req->data, REQUEST_MSG, len);

	*out = eap_payload_create_data(chunk_create((void*)req,
								   sizeof(eap_gtc_header_t) + len));
	return NEED_MORE;
}

METHOD(eap_method_t, process_peer, status_t,
	private_eap_method_t *this, eap_payload_t *in, eap_payload_t **out)
{
	eap_gtc_header_t *res;
	size_t len;

	len = strlen(MOCK_PW_MSG);
	this->identifier = in->get_identifier(in);
	res = alloca(sizeof(eap_gtc_header_t) + len);
	res->length = htons(sizeof(eap_gtc_header_t) + len);
	res->code = EAP_RESPONSE;
	res->identifier = this->identifier;
	res->type = EAP_GTC;
	memcpy(res->data, MOCK_PW_MSG, len);

	*out = eap_payload_create_data(chunk_create((void*)res,
								   sizeof(eap_gtc_header_t) + len));
	return NEED_MORE;
}

METHOD(eap_method_t, process_server, status_t,
	private_eap_method_t *this, eap_payload_t *in, eap_payload_t **out)
{
	chunk_t pass;

	pass = chunk_skip(in->get_data(in), 5);
	if (this->identifier != in->get_identifier(in) || !pass.len ||
		!chunk_equals_const(chunk_from_str(MOCK_PW_MSG), pass))
	{
		DBG1(DBG_IKE, "received invalid EAP-GTC message");
		return FAILED;
	}
	return SUCCESS;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_method_t *this, pen_t *vendor)
{
	*vendor = 0;
	return EAP_GTC;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_method_t *this, chunk_t *msk)
{
	return NOT_SUPPORTED;
}

METHOD(eap_method_t, get_identifier, uint8_t,
	private_eap_method_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_method_t *this, uint8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_method_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_method_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	free(this);
}

/**
 * Generic constructor
 */
static private_eap_method_t *mock_eap_create_generic(identification_t *server,
												  identification_t *peer)
{
	private_eap_method_t *this;

	INIT(this,
		.public = {
			.get_type = _get_type,
			.is_mutual = _is_mutual,
			.get_msk = _get_msk,
			.get_identifier = _get_identifier,
			.set_identifier = _set_identifier,
			.destroy = _destroy,
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
	);

	return this;
}

/*
 * Described in header
 */
eap_method_t *mock_eap_create_server(identification_t *server,
									 identification_t *peer)
{
	private_eap_method_t *this = mock_eap_create_generic(server, peer);

	this->public.initiate = _initiate_server;
	this->public.process = _process_server;

	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

/*
 * Described in header
 */
eap_method_t *mock_eap_create_peer(identification_t *server,
								   identification_t *peer)
{
	private_eap_method_t *this = mock_eap_create_generic(server, peer);

	this->public.initiate = _initiate_peer;
	this->public.process = _process_peer;

	return &this->public;
}
