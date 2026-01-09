/*
 *  Copyright 2011-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */


#include "empty-pkcs11.h"

// Algorithm definitions
#define ALG_RSA2048_PKCS1    0x01
#define ALG_RSA2048_PSS      0x02
#define ALG_RSA3072_PSS      0x03
#define ALG_ECDSA_SECP256R1  0x04

// Algorithm mapping structure
typedef struct {
    CK_BYTE key_id;  // CKA_ID value
    const char *algorithm;  // Algorithm string for HTTPS API
    const char *label;  // Key label
    CK_ULONG key_type;  // CKK_RSA or CKK_EC
} AlgorithmInfo;

static const AlgorithmInfo g_algorithms[] = {
    {ALG_RSA2048_PKCS1, "rsa-sign-pkcs1-2048-sha256", "RSA2048-PKCS1", CKK_RSA},
    {ALG_RSA2048_PSS,   "rsa-sign-pss-2048-sha256",   "RSA2048-PSS",   CKK_RSA},
    {ALG_RSA3072_PSS,   "rsa-sign-pss-3072-sha256",   "RSA3072-PSS",   CKK_RSA},
    {ALG_ECDSA_SECP256R1, "ec-sign-secp256r1-sha256", "ECDSA-secp256r1", CKK_EC}
};

#define NUM_ALGORITHMS (sizeof(g_algorithms) / sizeof(g_algorithms[0]))

// Module state
static int g_initialized = 0;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

// Session state
#define MAX_SESSIONS 16
static struct {
    CK_SESSION_HANDLE handle;
    CK_ULONG state;
    int in_use;
} g_sessions[MAX_SESSIONS];

// Object handles (keys)
#define MAX_OBJECTS 8
static struct {
    CK_OBJECT_HANDLE handle;
    CK_ATTRIBUTE attributes[8];
    int attr_count;  // Number of attributes set
    int in_use;
} g_objects[MAX_OBJECTS];

static CK_OBJECT_HANDLE g_next_object_handle = 1;
static CK_SESSION_HANDLE g_next_session_handle = 1;

// Slot and token info
#define SLOT_ID 0
#define TOKEN_LABEL "Secure HTTPS Signing Token"
#define MANUFACTURER_ID "Secure-PKCS11-HTTPS"
#define LIBRARY_DESCRIPTION "Secure PKCS#11 HTTPS Signing Module"

// Static storage for attribute values to avoid stack pointers
static CK_ULONG g_class_vals[MAX_OBJECTS];
static CK_ULONG g_key_type_vals[MAX_OBJECTS];
static CK_BBOOL g_sign_vals[MAX_OBJECTS];
static CK_BYTE g_key_id_vals[MAX_OBJECTS];

// Session state to track selected key and find objects search state
typedef struct {
    CK_OBJECT_HANDLE selected_key;
    int find_objects_index;  // Current index for C_FindObjects iteration
    int find_objects_active; // Whether a find operation is active
} SessionState;

static SessionState g_session_states[MAX_SESSIONS];

// Forward declarations
static CK_RV find_session(CK_SESSION_HANDLE hSession, int *idx);
static CK_RV find_object(CK_OBJECT_HANDLE hObject, int *idx);
static const char *get_algorithm_from_key(CK_OBJECT_HANDLE hKey);


CK_FUNCTION_LIST empty_pkcs11_2_40_functions = 
{
	{0x02, 0x28},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};


CK_INTERFACE empty_pkcs11_2_40_interface =
{
	(CK_CHAR*)"PKCS 11",
	&empty_pkcs11_2_40_functions,
	0
};


CK_FUNCTION_LIST_3_0  empty_pkcs11_3_1_functions =
{
	{0x03, 0x01},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
	&C_GetInterfaceList,
	&C_GetInterface,
	&C_LoginUser,
	&C_SessionCancel,
	&C_MessageEncryptInit,
	&C_EncryptMessage,
	&C_EncryptMessageBegin,
	&C_EncryptMessageNext,
	&C_MessageEncryptFinal,
	&C_MessageDecryptInit,
	&C_DecryptMessage,
	&C_DecryptMessageBegin,
	&C_DecryptMessageNext,
	&C_MessageDecryptFinal,
	&C_MessageSignInit,
	&C_SignMessage,
	&C_SignMessageBegin,
	&C_SignMessageNext,
	&C_MessageSignFinal,
	&C_MessageVerifyInit,
	&C_VerifyMessage,
	&C_VerifyMessageBegin,
	&C_VerifyMessageNext,
	&C_MessageVerifyFinal
};


CK_INTERFACE empty_pkcs11_3_1_interface =
{
	(CK_CHAR*)"PKCS 11",
	&empty_pkcs11_3_1_functions,
	0
};


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	UNUSED(pInitArgs);
	
	pthread_mutex_lock(&g_mutex);
	if (g_initialized) {
		pthread_mutex_unlock(&g_mutex);
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}
	
	// Initialize curl
	curl_global_init(CURL_GLOBAL_DEFAULT);
	
	// Initialize HTTPS client with configuration from environment variables
	const char *base_url = getenv("PKCS11_SIGNING_URL");
	const char *client_cert = getenv("PKCS11_CLIENT_CERT");
	const char *client_key = getenv("PKCS11_CLIENT_KEY");
	const char *environment = getenv("PKCS11_SIGNING_ENV");
	
	// Use default certificate location if not set
	if (!client_cert) {
		client_cert = "/etc/secure/pki/client.crt";
	}
	if (!client_key) {
		client_key = "/etc/secure/pki/client.key";
	}
	
	// Initialize HTTPS client only if configuration is available
	// Allow initialization even without HTTPS config (for slot listing, etc.)
	if (base_url || (client_cert && access(client_cert, R_OK) == 0)) {
		int init_result = https_client_init(base_url, client_cert, client_key, environment);
		if (init_result != 0) {
			// Don't fail initialization if HTTPS client init fails
		} else {
			// Test connectivity to HTTPS service (non-blocking, don't fail on error)
			https_test_connectivity();  // Result ignored - just a test
		}
	}
	
	// Initialize sessions and objects
	memset(g_sessions, 0, sizeof(g_sessions));
	memset(g_objects, 0, sizeof(g_objects));
	memset(g_session_states, 0, sizeof(g_session_states));
	
	// Create key objects for each supported algorithm
	for (size_t i = 0; i < NUM_ALGORITHMS && i < MAX_OBJECTS; i++) {
		g_objects[i].in_use = 1;
		g_objects[i].handle = g_next_object_handle++;
		
		// Set up attributes for signing key
		CK_ATTRIBUTE *attrs = g_objects[i].attributes;
		int attr_idx = 0;
		
		// CKA_CLASS
		attrs[attr_idx].type = CKA_CLASS;
		g_class_vals[i] = CKO_PRIVATE_KEY;
		attrs[attr_idx].pValue = &g_class_vals[i];
		attrs[attr_idx].ulValueLen = sizeof(CK_ULONG);
		attr_idx++;
		
		// CKA_KEY_TYPE
		attrs[attr_idx].type = CKA_KEY_TYPE;
		g_key_type_vals[i] = g_algorithms[i].key_type;
		attrs[attr_idx].pValue = &g_key_type_vals[i];
		attrs[attr_idx].ulValueLen = sizeof(CK_ULONG);
		attr_idx++;
		
		// CKA_SIGN
		attrs[attr_idx].type = CKA_SIGN;
		g_sign_vals[i] = CK_TRUE;
		attrs[attr_idx].pValue = &g_sign_vals[i];
		attrs[attr_idx].ulValueLen = sizeof(CK_BBOOL);
		attr_idx++;
		
		// CKA_ID (key_id to identify algorithm)
		attrs[attr_idx].type = CKA_ID;
		g_key_id_vals[i] = g_algorithms[i].key_id;
		attrs[attr_idx].pValue = &g_key_id_vals[i];
		attrs[attr_idx].ulValueLen = sizeof(CK_BYTE);
		attr_idx++;
		
		// CKA_LABEL
		attrs[attr_idx].type = CKA_LABEL;
		attrs[attr_idx].pValue = (void *)g_algorithms[i].label;
		attrs[attr_idx].ulValueLen = strlen(g_algorithms[i].label);
		attr_idx++;
		
		g_objects[i].attr_count = attr_idx;
	}
	
	g_initialized = 1;
	pthread_mutex_unlock(&g_mutex);
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	UNUSED(pReserved);
	
	pthread_mutex_lock(&g_mutex);
	if (!g_initialized) {
		pthread_mutex_unlock(&g_mutex);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	https_client_cleanup();
	curl_global_cleanup();
	g_initialized = 0;
	pthread_mutex_unlock(&g_mutex);
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	// Allow querying info even if not initialized (some tools do this)
	if (!pInfo) {
		return CKR_ARGUMENTS_BAD;
	}
	
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 40;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	{
		size_t len = strlen(MANUFACTURER_ID);
		size_t copy_len = (len < sizeof(pInfo->manufacturerID)) ? len : sizeof(pInfo->manufacturerID) - 1;
		memcpy(pInfo->manufacturerID, MANUFACTURER_ID, copy_len);
	}
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	{
		size_t len = strlen(LIBRARY_DESCRIPTION);
		size_t copy_len = (len < sizeof(pInfo->libraryDescription)) ? len : sizeof(pInfo->libraryDescription) - 1;
		memcpy(pInfo->libraryDescription, LIBRARY_DESCRIPTION, copy_len);
	}
	pInfo->libraryVersion.major = 1;
	pInfo->libraryVersion.minor = 0;
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &empty_pkcs11_2_40_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	UNUSED(tokenPresent);  // We always have one slot with token
	
	// Allow querying slots even if not initialized (some tools do this)
	if (!pulCount) {
		return CKR_ARGUMENTS_BAD;
	}
	
	// We always have one slot with a token present
	CK_ULONG slotCount = 1;
	
	if (pSlotList) {
		if (*pulCount < slotCount) {
			*pulCount = slotCount;
			return CKR_BUFFER_TOO_SMALL;
		}
		pSlotList[0] = SLOT_ID;
		*pulCount = slotCount;
	} else {
		// Just return the count
		*pulCount = slotCount;
	}
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	// Allow querying slot info even if not initialized
	if (!pInfo) {
		return CKR_ARGUMENTS_BAD;
	}
	if (slotID != SLOT_ID) {
		return CKR_SLOT_ID_INVALID;
	}
	
	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	{
		const char *str = "HTTPS Signing Slot";
		size_t len = strlen(str);
		size_t copy_len = (len < sizeof(pInfo->slotDescription)) ? len : sizeof(pInfo->slotDescription) - 1;
		memcpy(pInfo->slotDescription, str, copy_len);
	}
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	{
		size_t len = strlen(MANUFACTURER_ID);
		size_t copy_len = (len < sizeof(pInfo->manufacturerID)) ? len : sizeof(pInfo->manufacturerID) - 1;
		memcpy(pInfo->manufacturerID, MANUFACTURER_ID, copy_len);
	}
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	// Allow querying token info even if not initialized
	if (!pInfo) {
		return CKR_ARGUMENTS_BAD;
	}
	if (slotID != SLOT_ID) {
		return CKR_SLOT_ID_INVALID;
	}
	
	memset(pInfo->label, ' ', sizeof(pInfo->label));
	{
		size_t len = strlen(TOKEN_LABEL);
		size_t copy_len = (len < sizeof(pInfo->label)) ? len : sizeof(pInfo->label) - 1;
		memcpy(pInfo->label, TOKEN_LABEL, copy_len);
	}
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	{
		size_t len = strlen(MANUFACTURER_ID);
		size_t copy_len = (len < sizeof(pInfo->manufacturerID)) ? len : sizeof(pInfo->manufacturerID) - 1;
		memcpy(pInfo->manufacturerID, MANUFACTURER_ID, copy_len);
	}
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	{
		const char *str = "v1.0";
		size_t len = strlen(str);
		size_t copy_len = (len < sizeof(pInfo->model)) ? len : sizeof(pInfo->model) - 1;
		memcpy(pInfo->model, str, copy_len);
	}
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	{
		const char *str = "SECURE-HTTPS-01";
		size_t len = strlen(str);
		size_t copy_len = (len < sizeof(pInfo->serialNumber)) ? len : sizeof(pInfo->serialNumber) - 1;
		memcpy(pInfo->serialNumber, str, copy_len);
	}
	
	// Set flags: token is present, initialized, and has RNG
	pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_RNG;
	pInfo->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulSessionCount = 0;
	pInfo->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulRwSessionCount = 0;
	pInfo->ulMaxPinLen = 0;
	pInfo->ulMinPinLen = 0;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	UNUSED(slotID);
	
	if (!pulCount) {
		return CKR_ARGUMENTS_BAD;
	}
	
	// We support: CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_ECDSA
	static const CK_MECHANISM_TYPE mechanisms[] = {
		CKM_RSA_PKCS,      // RSA2048 PKCS#1
		CKM_RSA_PKCS_PSS,  // RSA2048/3072 PSS
		CKM_ECDSA          // ECDSA secp256r1
	};
	const CK_ULONG mechanism_count = sizeof(mechanisms) / sizeof(mechanisms[0]);
	
	if (!pMechanismList) {
		// Just return the count
		*pulCount = mechanism_count;
		return CKR_OK;
	}
	
	if (*pulCount < mechanism_count) {
		*pulCount = mechanism_count;
		return CKR_BUFFER_TOO_SMALL;
	}
	
	memcpy(pMechanismList, mechanisms, sizeof(mechanisms));
	*pulCount = mechanism_count;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	UNUSED(slotID);
	
	if (!pInfo) {
		return CKR_ARGUMENTS_BAD;
	}
	
	// Initialize with defaults
	pInfo->ulMinKeySize = 0;
	pInfo->ulMaxKeySize = 0;
	pInfo->flags = 0;
	
	switch (type) {
		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 256;  // 2048 bits
			pInfo->ulMaxKeySize = 256;  // 2048 bits
			pInfo->flags = CKF_HW | CKF_SIGN;
			break;
		case CKM_RSA_PKCS_PSS:
			pInfo->ulMinKeySize = 256;  // 2048 bits
			pInfo->ulMaxKeySize = 384;  // 3072 bits
			pInfo->flags = CKF_HW | CKF_SIGN;
			break;
		case CKM_ECDSA:
			pInfo->ulMinKeySize = 32;   // 256 bits (secp256r1)
			pInfo->ulMaxKeySize = 32;   // 256 bits
			pInfo->flags = CKF_HW | CKF_SIGN;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	UNUSED(slotID);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pLabel);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(pPin);
	UNUSED(ulPinLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	UNUSED(hSession);
	UNUSED(pOldPin);
	UNUSED(ulOldLen);
	UNUSED(pNewPin);
	UNUSED(ulNewLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	UNUSED(pApplication);
	UNUSED(Notify);
	
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!phSession) {
		return CKR_ARGUMENTS_BAD;
	}
	if (slotID != SLOT_ID) {
		return CKR_SLOT_ID_INVALID;
	}
	
	pthread_mutex_lock(&g_mutex);
	
	// Find free session slot
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		if (!g_sessions[i].in_use) {
			g_sessions[i].in_use = 1;
			g_sessions[i].handle = g_next_session_handle++;
			g_sessions[i].state = (flags & CKF_RW_SESSION) ? 
				CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
			*phSession = g_sessions[i].handle;
			pthread_mutex_unlock(&g_mutex);
			return CKR_OK;
		}
	}
	
	pthread_mutex_unlock(&g_mutex);
	return CKR_SESSION_COUNT;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	if (find_session(hSession, &idx) == CKR_OK) {
		g_sessions[idx].in_use = 0;
		pthread_mutex_unlock(&g_mutex);
		return CKR_OK;
	}
	pthread_mutex_unlock(&g_mutex);
	return CKR_SESSION_HANDLE_INVALID;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (slotID != SLOT_ID) {
		return CKR_SLOT_ID_INVALID;
	}
	
	pthread_mutex_lock(&g_mutex);
	for (int i = 0; i < MAX_SESSIONS; i++) {
		g_sessions[i].in_use = 0;
	}
	pthread_mutex_unlock(&g_mutex);
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pInfo) {
		return CKR_ARGUMENTS_BAD;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_session(hSession, &idx);
	if (rv == CKR_OK) {
		pInfo->state = g_sessions[idx].state;
		pInfo->flags = CKF_SERIAL_SESSION;
		pInfo->ulDeviceError = 0;
	}
	pthread_mutex_unlock(&g_mutex);
	
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(pulOperationStateLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(ulOperationStateLen);
	UNUSED(hEncryptionKey);
	UNUSED(hAuthenticationKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_session(hSession, &idx);
	if (rv == CKR_OK) {
		// For this minimal implementation, we accept any login
		if (g_sessions[idx].state == CKS_RO_PUBLIC_SESSION) {
			g_sessions[idx].state = CKS_RO_USER_FUNCTIONS;
		} else {
			g_sessions[idx].state = CKS_RW_USER_FUNCTIONS;
		}
	}
	pthread_mutex_unlock(&g_mutex);
	
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_session(hSession, &idx);
	if (rv == CKR_OK) {
		if (g_sessions[idx].state == CKS_RO_USER_FUNCTIONS) {
			g_sessions[idx].state = CKS_RO_PUBLIC_SESSION;
		} else if (g_sessions[idx].state == CKS_RW_USER_FUNCTIONS) {
			g_sessions[idx].state = CKS_RW_PUBLIC_SESSION;
		}
	}
	pthread_mutex_unlock(&g_mutex);
	
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	UNUSED(hSession);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phNewObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	UNUSED(hSession);
	UNUSED(hObject);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pulSize);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pTemplate) {
		return CKR_ARGUMENTS_BAD;
	}
	
	pthread_mutex_lock(&g_mutex);
	int obj_idx;
	CK_RV rv = find_object(hObject, &obj_idx);
	if (rv != CKR_OK) {
		pthread_mutex_unlock(&g_mutex);
		return rv;
	}
	
	CK_ATTRIBUTE *obj_attrs = g_objects[obj_idx].attributes;
	int obj_attr_count = g_objects[obj_idx].attr_count;
	
	for (CK_ULONG i = 0; i < ulCount; i++) {
		pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
		int found = 0;
		for (int j = 0; j < obj_attr_count; j++) {
			if (obj_attrs[j].type == pTemplate[i].type) {
				found = 1;
				if (pTemplate[i].pValue) {
					if (pTemplate[i].ulValueLen >= obj_attrs[j].ulValueLen) {
						memcpy(pTemplate[i].pValue, obj_attrs[j].pValue, obj_attrs[j].ulValueLen);
						pTemplate[i].ulValueLen = obj_attrs[j].ulValueLen;
					} else {
						pTemplate[i].ulValueLen = obj_attrs[j].ulValueLen;
						pthread_mutex_unlock(&g_mutex);
						return CKR_BUFFER_TOO_SMALL;
					}
				} else {
					pTemplate[i].ulValueLen = obj_attrs[j].ulValueLen;
				}
				break;
			}
		}
		if (!found) {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
		}
	}
	
	pthread_mutex_unlock(&g_mutex);
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(pTemplate);
	UNUSED(ulCount);
	
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_session(hSession, &idx);
	if (rv == CKR_OK) {
		// Reset search state for this session
		g_session_states[idx].find_objects_index = 0;
		g_session_states[idx].find_objects_active = 1;
	}
	pthread_mutex_unlock(&g_mutex);
	
	if (rv != CKR_OK) {
		return rv;
	}
	
	// Key objects are already created in C_Initialize
	// This function just prepares for object enumeration
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!phObject || !pulObjectCount) {
		return CKR_ARGUMENTS_BAD;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_session(hSession, &idx);
	if (rv != CKR_OK) {
		pthread_mutex_unlock(&g_mutex);
		return rv;
	}
	
	// Check if find operation is active
	if (!g_session_states[idx].find_objects_active) {
		pthread_mutex_unlock(&g_mutex);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	
	*pulObjectCount = 0;
	// Continue from where we left off
	int start_idx = g_session_states[idx].find_objects_index;
	for (int i = start_idx; i < MAX_OBJECTS && *pulObjectCount < ulMaxObjectCount; i++) {
		if (g_objects[i].in_use) {
			phObject[*pulObjectCount] = g_objects[i].handle;
			(*pulObjectCount)++;
		}
	}
	// Update the index for next call
	g_session_states[idx].find_objects_index = start_idx + *pulObjectCount;
	
	pthread_mutex_unlock(&g_mutex);
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_session(hSession, &idx);
	if (rv == CKR_OK) {
		// Reset find operation state
		g_session_states[idx].find_objects_index = 0;
		g_session_states[idx].find_objects_active = 0;
	}
	pthread_mutex_unlock(&g_mutex);
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pEncryptedData);
	UNUSED(pulEncryptedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastEncryptedPart);
	UNUSED(pulLastEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedData);
	UNUSED(ulEncryptedDataLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastPart);
	UNUSED(pulLastPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	UNUSED(hSession);
	UNUSED(pMechanism);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pMechanism) {
		return CKR_ARGUMENTS_BAD;
	}
	
	pthread_mutex_lock(&g_mutex);
	int session_idx;
	CK_RV rv = find_session(hSession, &session_idx);
	if (rv == CKR_OK) {
		// Store selected key in session state
		g_session_states[session_idx].selected_key = hKey;
	}
	pthread_mutex_unlock(&g_mutex);
	
	// For minimal implementation, we accept any mechanism
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pData || !pulSignatureLen) {
		return CKR_ARGUMENTS_BAD;
	}
	
	// Get the key object from session (stored in C_SignInit)
	pthread_mutex_lock(&g_mutex);
	int session_idx;
	CK_RV rv = find_session(hSession, &session_idx);
	CK_OBJECT_HANDLE hKey = 0;
	if (rv == CKR_OK) {
		hKey = g_session_states[session_idx].selected_key;
	}
	pthread_mutex_unlock(&g_mutex);
	
	if (hKey == 0) {
		// Fallback: use first available key (for backward compatibility)
		pthread_mutex_lock(&g_mutex);
		for (int i = 0; i < MAX_OBJECTS; i++) {
			if (g_objects[i].in_use) {
				hKey = g_objects[i].handle;
				break;
			}
		}
		pthread_mutex_unlock(&g_mutex);
		
		if (hKey == 0) {
			return CKR_KEY_HANDLE_INVALID;
		}
	}
	
	// Get algorithm from key
	const char *algorithm = get_algorithm_from_key(hKey);
	if (!algorithm) {
		return CKR_FUNCTION_FAILED;
	}
	
	// If pSignature is NULL, just return the expected signature length
	size_t expected_sig_len = 256;  // Default to RSA2048
	if (strstr(algorithm, "3072")) {
		expected_sig_len = 384;
	} else if (strstr(algorithm, "ec-")) {
		expected_sig_len = 64;
	}
	
	if (!pSignature) {
		// Just return the length
		*pulSignatureLen = expected_sig_len;
		return CKR_OK;
	}
	
	// Compute SHA-256 hash of the input data using EVP API
	unsigned char hash[32];  // SHA-256 produces 32 bytes
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		return CKR_DEVICE_MEMORY;
	}
	
	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
		EVP_DigestUpdate(mdctx, pData, ulDataLen) != 1 ||
		EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
		EVP_MD_CTX_free(mdctx);
		return CKR_FUNCTION_FAILED;
	}
	EVP_MD_CTX_free(mdctx);
	
	// Request signature from HTTPS service with algorithm
	unsigned char *signature = NULL;
	size_t signature_len = 0;
	
	int ret = https_request_signature(hash, 32, algorithm, &signature, &signature_len);
	if (ret != 0) {
		return CKR_FUNCTION_FAILED;
	}
	
	if (*pulSignatureLen < signature_len) {
		*pulSignatureLen = signature_len;
		if (signature) {
			free(signature);
			signature = NULL;
		}
		return CKR_BUFFER_TOO_SMALL;
	}
	
	memcpy(pSignature, signature, signature_len);
	*pulSignatureLen = signature_len;
	// Free signature after copying
	if (signature) {
		free(signature);
		signature = NULL;
	}
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pMechanism) {
		return CKR_ARGUMENTS_BAD;
	}
	
	pthread_mutex_lock(&g_mutex);
	int session_idx;
	CK_RV rv = find_session(hSession, &session_idx);
	if (rv == CKR_OK) {
		g_session_states[session_idx].selected_key = hKey;
	}
	pthread_mutex_unlock(&g_mutex);
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	
	if (!g_initialized) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pData || !pSignature) {
		return CKR_ARGUMENTS_BAD;
	}
	
	// Get algorithm from session (stored in C_VerifyInit)
	pthread_mutex_lock(&g_mutex);
	int session_idx;
	CK_RV rv = find_session(hSession, &session_idx);
	CK_OBJECT_HANDLE hKey = 0;
	if (rv == CKR_OK) {
		hKey = g_session_states[session_idx].selected_key;
	}
	pthread_mutex_unlock(&g_mutex);
	
	if (hKey == 0) {
		return CKR_KEY_HANDLE_INVALID;
	}
	
	// Get algorithm from key
	const char *algorithm = get_algorithm_from_key(hKey);
	if (!algorithm) {
		return CKR_FUNCTION_FAILED;
	}
	
	// Compute SHA-256 hash of the input data
	unsigned char hash[32];
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		return CKR_DEVICE_MEMORY;
	}
	
	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
		EVP_DigestUpdate(mdctx, pData, ulDataLen) != 1 ||
		EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
		EVP_MD_CTX_free(mdctx);
		return CKR_FUNCTION_FAILED;
	}
	EVP_MD_CTX_free(mdctx);
	
	// Get public key from HTTPS service
	char *public_key_pem = NULL;
	if (https_get_public_key(algorithm, &public_key_pem) != 0) {
		return CKR_FUNCTION_FAILED;
	}
	
	// Verify signature
	int ret = https_verify_signature(hash, 32, pSignature, ulSignatureLen,
									 public_key_pem, algorithm);
	free(public_key_pem);
	
	if (ret != 0) {
		return CKR_SIGNATURE_INVALID;
	}
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pPublicKeyTemplate);
	UNUSED(ulPublicKeyAttributeCount);
	UNUSED(pPrivateKeyTemplate);
	UNUSED(ulPrivateKeyAttributeCount);
	UNUSED(phPublicKey);
	UNUSED(phPrivateKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hWrappingKey);
	UNUSED(hKey);
	UNUSED(pWrappedKey);
	UNUSED(pulWrappedKeyLen);
	
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hUnwrappingKey);
	UNUSED(pWrappedKey);
	UNUSED(ulWrappedKeyLen);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hBaseKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	UNUSED(hSession);
	UNUSED(pSeed);
	UNUSED(ulSeedLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	UNUSED(hSession);
	UNUSED(RandomData);
	UNUSED(ulRandomLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	UNUSED(flags);
	UNUSED(pSlot);
	UNUSED(pReserved);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pInterfacesList)
	{
		*pulCount = 2;
	}
	else
	{
		if (*pulCount < 2)
			return CKR_BUFFER_TOO_SMALL;

		pInterfacesList[0].pInterfaceName = empty_pkcs11_2_40_interface.pInterfaceName;
		pInterfacesList[0].pFunctionList = empty_pkcs11_2_40_interface.pFunctionList;
		pInterfacesList[0].flags = empty_pkcs11_2_40_interface.flags;

		pInterfacesList[1].pInterfaceName = empty_pkcs11_3_1_interface.pInterfaceName;
		pInterfacesList[1].pFunctionList = empty_pkcs11_3_1_interface.pFunctionList;
		pInterfacesList[1].flags = empty_pkcs11_3_1_interface.flags;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	if (NULL == ppInterface)
		return CKR_ARGUMENTS_BAD;

	if (flags != 0)
	{
		*ppInterface = NULL;
		return CKR_OK;
	}

	if (NULL != pInterfaceName)
	{
		const char* requested_interface_name = (const char*)pInterfaceName;
		const char* supported_interface_name = "PKCS 11";

		if (strlen(requested_interface_name) != strlen(supported_interface_name) || 0 != strcmp(requested_interface_name, supported_interface_name))
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	if (NULL != pVersion)
	{
		if (pVersion->major == empty_pkcs11_2_40_functions.version.major && pVersion->minor == empty_pkcs11_2_40_functions.version.minor)
		{
			*ppInterface = &empty_pkcs11_2_40_interface;
			return CKR_OK;
		}
		else if (pVersion->major == empty_pkcs11_3_1_functions.version.major && pVersion->minor == empty_pkcs11_3_1_functions.version.minor)
		{
			*ppInterface = &empty_pkcs11_3_1_interface;
			return CKR_OK;
		}
		else
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	*ppInterface = &empty_pkcs11_3_1_interface;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pUsername);
	UNUSED(ulUsernameLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pPlaintext);
	UNUSED(ulPlaintextLen);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pPlaintextPart);
	UNUSED(ulPlaintextPartLen);
	UNUSED(pCiphertextPart);
	UNUSED(pulCiphertextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(pPlaintext);
	UNUSED(pulPlaintextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pCiphertextPart);
	UNUSED(ulCiphertextPartLen);
	UNUSED(pPlaintextPart);
	UNUSED(pulPlaintextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Helper function to find session
static CK_RV find_session(CK_SESSION_HANDLE hSession, int *idx)
{
	for (int i = 0; i < MAX_SESSIONS; i++) {
		if (g_sessions[i].in_use && g_sessions[i].handle == hSession) {
			*idx = i;
			return CKR_OK;
		}
	}
	return CKR_SESSION_HANDLE_INVALID;
}

// Helper function to find object
static CK_RV find_object(CK_OBJECT_HANDLE hObject, int *idx)
{
	for (int i = 0; i < MAX_OBJECTS; i++) {
		if (g_objects[i].in_use && g_objects[i].handle == hObject) {
			*idx = i;
			return CKR_OK;
		}
	}
	return CKR_OBJECT_HANDLE_INVALID;
}

// Helper function to get algorithm from key object
static const char *get_algorithm_from_key(CK_OBJECT_HANDLE hKey)
{
	pthread_mutex_lock(&g_mutex);
	int idx;
	CK_RV rv = find_object(hKey, &idx);
	if (rv != CKR_OK) {
		pthread_mutex_unlock(&g_mutex);
		return NULL;
	}
	
	// Find CKA_ID in attributes
	CK_BYTE key_id = 0;
	for (int i = 0; i < g_objects[idx].attr_count; i++) {
		if (g_objects[idx].attributes[i].type == CKA_ID) {
			key_id = *(CK_BYTE *)g_objects[idx].attributes[i].pValue;
			break;
		}
	}
	pthread_mutex_unlock(&g_mutex);
	
	// Find algorithm by key_id
	for (size_t i = 0; i < NUM_ALGORITHMS; i++) {
		if (g_algorithms[i].key_id == key_id) {
			return g_algorithms[i].algorithm;
		}
	}
	
	// Default to RSA2048 PKCS#1 if not found
	return "rsa-sign-pkcs1-2048-sha256";
}
