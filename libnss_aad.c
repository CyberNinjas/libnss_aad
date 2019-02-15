#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include "cJSON.h"
#include "sds.h"

#define MIN_UID_NUMBER 500
#define MIN_GID_NUMBER 500
#define CONF_FILE "/etc/libnss-aad.conf"
#define RESOURCE_ID "00000002-0000-0000-c000-000000000000"
#define USER_AGENT "libnss_aad/1.0"
#define USER_FIELD "mailNickname"

struct response
{
	char *data;
	size_t size;
};

static size_t response_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct response *resp = (struct response*)userp;

	char *ptr = realloc(resp->data, resp->size + realsize + 1);
	if(ptr == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	resp->data = ptr;
	memcpy(&(resp->data[resp->size]), contents, realsize);
	resp->size += realsize;
	resp->data[resp->size] = 0;

	return realsize;
}

static char *load_file(char const* path)
{
	char *buffer;
	long length;
	FILE *f = fopen(path, "rb");
	if(f)
	{
		fseek(f, 0, SEEK_END);
		length = ftell(f);
		fseek(f, 0, SEEK_SET);
		buffer = (char *) malloc((length + 1) * sizeof(char));
		if (buffer)
		{
			fread(buffer, sizeof(char), length, f);
		}
		fclose(f);
	}
	buffer[length] = '\0';
	return buffer;
}

static char *get_static(char **buffer, size_t *buflen, int len)
{
	char *result;

	if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
		return NULL;
	}

	result = *buffer;
	*buffer += len;
	*buflen -= len;

	return result;
}

static cJSON *get_oauth2_token(char *client_id, char *client_secret, char *domain)
{
	CURL *curl_handle;
	CURLcode res;
	cJSON *token_data, *token;
	struct response resp;

	resp.data = malloc(1);
	resp.size = 0;

	/* https://login.microsoftonline.com/<domain>/oauth2/token */
	sds endpoint = sdsnew("https://login.microsoftonline.com/");
	endpoint = sdscat(endpoint, domain);
	endpoint = sdscat(endpoint, "/oauth2/token");

	//  printf("endpoint: %s\n", endpoint);

	sds post_body = sdsnew("grant_type=client_credentials&client_secret=");
	post_body = sdscat(post_body, client_secret);
	post_body = sdscat(post_body, "&client_id=");
	post_body = sdscat(post_body, client_id);
	post_body = sdscat(post_body, "&resource=");
	post_body = sdscat(post_body, RESOURCE_ID);

	//  printf("post_body: %s\n", post_body);

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_body);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, response_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&resp);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);

	/* https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html */
	//curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

	res = curl_easy_perform(curl_handle);

	/* check for errors */
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
	}
	else {
		token_data = cJSON_Parse(resp.data);

		if(token_data == NULL) {
			fprintf(stderr, "cJSON_Parse() failed\n");
			return NULL;
		}
	}

	curl_easy_cleanup(curl_handle);
	sdsfree(endpoint);
	sdsfree(post_body);
	free(resp.data);

	token = cJSON_GetObjectItem(token_data, "access_token");
	return (token) ? token : NULL;
}

static int verify_user(cJSON *auth_token, char *domain, char *name)
{
	CURL *curl_handle;
	CURLcode res;
	cJSON *user_data;
	sds auth_header = sdsnew("Authorization: Bearer ");
	sds endpoint = sdsnew("https://graph.windows.net/");
	struct response resp;
	struct curl_slist *headers = NULL;
	char *user_field;

	resp.data = malloc(1);
	resp.size = 0;

	auth_header = sdscat(auth_header, auth_token->valuestring);
	headers = curl_slist_append(headers, auth_header);

	/* https://graph.windows.net/<domain>/users/<username>@<domain>?api-version=1.6 */
	endpoint = sdscat(endpoint, domain);
	endpoint = sdscat(endpoint, "/users/");
	endpoint = sdscat(endpoint, name);
	endpoint = sdscat(endpoint, "@");
	endpoint = sdscat(endpoint, domain);
	endpoint = sdscat(endpoint, "?api-version=1.6");

	//  printf("endpoint: %s\n", endpoint);

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
	curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, response_callback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&resp);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);
	curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);

	/* https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html */
        //curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

	res = curl_easy_perform(curl_handle);


	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
	}
	else {
		user_data = cJSON_Parse(resp.data);

		if(user_data == NULL)
		{
			fprintf(stderr, "cJSON_Parse() failed\n");
			return EXIT_FAILURE;
		}

		if(cJSON_GetObjectItem(user_data, "odata.error") != NULL)
		{
			fprintf(stderr, "returned odata.error\n");
			return EXIT_FAILURE;
		}
	}

	curl_easy_cleanup(curl_handle);
	curl_slist_free_all(headers);
	sdsfree(auth_header);
	sdsfree(endpoint);
	free(resp.data);

        user_field = cJSON_GetObjectItem(user_data, USER_FIELD)->valuestring;
	return (user_field && strcmp(user_field, name) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

enum nss_status _nss_aad_getpwnam_r(const char *name, struct passwd *p, char *buffer, size_t buflen, int *errnop)
{
	char *config_file, *domain; 
	cJSON *config, *client, *token;

	config_file = load_file(CONF_FILE);
	if(config_file == NULL)
	{
		return NSS_STATUS_NOTFOUND;
	}

	config = cJSON_Parse(config_file);

	client = cJSON_GetObjectItem(config, "client");
	domain = cJSON_GetObjectItem(config, "domain")->valuestring;

	curl_global_init(CURL_GLOBAL_ALL);

	token = get_oauth2_token(cJSON_GetObjectItem(client, "id")->valuestring,
			cJSON_GetObjectItem(client, "secret")->valuestring, domain);

	if(!verify_user(token, domain, (char *) name))
	{
		if((p->pw_name = get_static(&buffer, &buflen, strlen(name) + 1)) == NULL)
			return NSS_STATUS_TRYAGAIN;

		strcpy(p->pw_name, name);

		if((p->pw_passwd = get_static(&buffer, &buflen, strlen("x") + 1)) == NULL)
			return NSS_STATUS_TRYAGAIN;

		strcpy(p->pw_passwd, "x");

/*
		if((p->pw_uid = get_static(&buffer, &buflen, strlen(p->pw_uid) + 1)) == NULL)
			return NSS_STATUS_TRYAGAIN;

		strcpy(p->pw_uid, MIN_UID_NUMBER); */
	}
	else 
	{
		curl_global_cleanup();
		return NSS_STATUS_TRYAGAIN;
	}

	curl_global_cleanup();
	return NSS_STATUS_SUCCESS;
}
