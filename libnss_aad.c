#include <cjson/cJSON.h>
#include <crypt.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <nss.h>
#include <pwd.h>
#include <sds/sds.h>
#include <shadow.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <xcrypt.h>

#define CONF_FILE "/etc/libnss-aad.conf"
#define MAX_PASSWD_LENGTH 32
#define MIN_GID 1000
#define MIN_UID 1000
#define PASSWD_FILE "/etc/passwd"
#define RESOURCE_ID "00000002-0000-0000-c000-000000000000"
#define SHADOW_FILE "/etc/shadow"
#define SHELL "/bin/sh"
#define USER_AGENT "libnss_aad/1.0"
#define USER_FIELD "mailNickname"

struct charset {
    char const *const c;
    uint32_t const l;
};

struct response {
    char *data;
    size_t size;
};

static size_t response_callback(void *contents, size_t size, size_t nmemb,
				void *userp)
{
    size_t realsize = size * nmemb;
    struct response *resp = (struct response *) userp;

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (ptr == NULL) {
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

static char *load_file(const char *path)
{
    char *buffer;
    long length;
    FILE *fd = fopen(path, "rb");
    if (fd) {
	fseek(fd, 0, SEEK_END);
	length = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	buffer = (char *) malloc((length + 1) * sizeof(char));
	if (buffer) {
	    fread(buffer, sizeof(char), length, fd);
	}
	fclose(fd);
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

static char *generate_passwd(void)
{
    if (sodium_init() < 0) {
	fprintf(stderr, "libsodium could not be initialized\n");
	return NULL;
    }

    uintmax_t const length = MAX_PASSWD_LENGTH;

    struct charset lower = {
	"abcdefghijklmnopqrstuvwxyz",
	(uint32_t) strlen(lower.c)
    };

    struct charset numeric = {
	"0123456789",
	(uint32_t) strlen(numeric.c)
    };

    struct charset special = {
	"!@#$%^&*()-_=+`~[]{}\\|;:'\",.<>/?",
	(uint32_t) strlen(special.c)
    };

    struct charset upper = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	(uint32_t) strlen(upper.c)
    };

    uint32_t const chars_l = lower.l + numeric.l + special.l + upper.l;

    char *const chars = malloc(chars_l + 1);

    if (chars == NULL) {
	fprintf(stderr, "failed to allocate memory for string\n");
	return NULL;
    }

    chars[0] = '\0';

    char *endptr = chars;

    char *passwd = (char *) malloc((length + 1) * sizeof(char));

    if (passwd == NULL) {
	fprintf(stderr, "failed to allocate memory for string\n");
	return NULL;
    }

    memcpy(endptr, lower.c, lower.l);
    endptr += lower.l;

    memcpy(endptr, numeric.c, numeric.l);
    endptr += numeric.l;

    memcpy(endptr, special.c, special.l);
    endptr += special.l;

    memcpy(endptr, upper.c, upper.l);

    for (uintmax_t i = 0; i < length; ++i) {
	passwd[i] = chars[randombytes_uniform(chars_l)];
    }

    passwd[length + 1] = '\0';

    free(chars);

    char entropy[16];
    int fd;

    fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
	printf("Can't open /dev/urandom\n");
	return NULL;
    }

    if (read(fd, entropy, sizeof(entropy)) != sizeof(entropy)) {
	printf("Not enough entropy\n");
	return NULL;
    }

    close(fd);

    return xcrypt(passwd,
		  xcrypt_gensalt("$2a$", 12, entropy, sizeof(entropy)));
}

static cJSON *get_oauth2_token(char *client_id, char *client_secret,
			       char *domain)
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

    sds post_body = sdsnew("grant_type=client_credentials&client_secret=");
    post_body = sdscat(post_body, client_secret);
    post_body = sdscat(post_body, "&client_id=");
    post_body = sdscat(post_body, client_id);
    post_body = sdscat(post_body, "&resource=");
    post_body = sdscat(post_body, RESOURCE_ID);

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, post_body);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
		     response_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);

    /* https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html */
    //curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl_handle);

    /* check for errors */
    if (res != CURLE_OK) {
	fprintf(stderr, "curl_easy_perform() failed: %s\n",
		curl_easy_strerror(res));
    } else {
	token_data = cJSON_Parse(resp.data);

	if (token_data == NULL) {
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

static int verify_user(cJSON * auth_token, char *domain, const char *name)
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

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
		     response_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &resp);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);

    /* https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html */
    //curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

    res = curl_easy_perform(curl_handle);


    if (res != CURLE_OK) {
	fprintf(stderr, "curl_easy_perform() failed: %s\n",
		curl_easy_strerror(res));
    } else {
	user_data = cJSON_Parse(resp.data);

	if (user_data == NULL) {
	    fprintf(stderr, "cJSON_Parse() failed\n");
	    return EXIT_FAILURE;
	}

	if (cJSON_GetObjectItem(user_data, "odata.error") != NULL) {
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
    return (user_field
	    && strcmp(user_field,
		      name) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int write_entry(const char *fp, void *userp)
{
    int ret = EXIT_FAILURE;
    FILE *fd = fopen(fp, "a");
    if (fd) {
	fseek(fd, 0, SEEK_END);
	if (strcmp(fp, PASSWD_FILE) == 0) {
	    struct passwd *p = (struct passwd *) userp;
	    ret = putpwent(p, fd);
	}

	if (strcmp(fp, SHADOW_FILE) == 0) {
	    struct spwd *s = (struct spwd *) userp;
	    ret = putspent(s, fd);
	}
	fclose(fd);
    }
    return ret;
}

enum nss_status _nss_aad_getpwnam_r(const char *name, struct passwd *p,
				    char *buffer, size_t buflen,
				    int *errnop)
{
    char *config_file, *domain, *shell;
    cJSON *config, *client, *shell_cfg, *token, *user_cfg;
    int ret = 0, user_id = MIN_UID;
    sds home_dir = sdsnew("/home/");
    struct group *group;
    struct passwd *user;

    (void) (errnop);		/* unused-parameter */

    config_file = load_file(CONF_FILE);
    if (config_file == NULL) {
	return NSS_STATUS_NOTFOUND;
    }

    config = cJSON_Parse(config_file);
    if (config == NULL) {
	return NSS_STATUS_NOTFOUND;
    }

    client = cJSON_GetObjectItem(config, "client");

    domain = cJSON_GetObjectItem(config, "domain")->valuestring;

    user_cfg = cJSON_GetObjectItem(config, "user");

    user = getpwuid(user_id);

    group = getgrnam(cJSON_GetObjectItem(user_cfg, "group")->valuestring);

    shell_cfg = cJSON_GetObjectItem(user_cfg, "shell");

    shell = (shell_cfg) ? shell_cfg->valuestring : sdsnew(SHELL);

    home_dir = sdscat(home_dir, name);

    curl_global_init(CURL_GLOBAL_ALL);

    token =
	get_oauth2_token(cJSON_GetObjectItem(client, "id")->valuestring,
			 cJSON_GetObjectItem(client,
					     "secret")->valuestring,
			 domain);

    ret = verify_user(token, domain, name);

    curl_global_cleanup();

    if (!ret) {
	if ((p->pw_name =
	     get_static(&buffer, &buflen, strlen(name) + 1)) == NULL)
	    return NSS_STATUS_TRYAGAIN;

	strcpy(p->pw_name, name);

	if ((p->pw_passwd =
	     get_static(&buffer, &buflen, strlen("x") + 1)) == NULL)
	    return NSS_STATUS_TRYAGAIN;

	strcpy(p->pw_passwd, "x");

	while (user != NULL) {
	    user = getpwuid(++user_id);
	}
	p->pw_uid = user_id;

	p->pw_gid = (group) ? group->gr_gid : MIN_GID;

	if ((p->pw_gecos =
	     get_static(&buffer, &buflen, strlen("\0") + 1)) == NULL)
	    return NSS_STATUS_TRYAGAIN;

	strcpy(p->pw_gecos, "\0");

	if ((p->pw_dir =
	     get_static(&buffer, &buflen, strlen(home_dir) + 1)) == NULL)
	    return NSS_STATUS_TRYAGAIN;

	strcpy(p->pw_dir, home_dir);

	if ((p->pw_shell =
	     get_static(&buffer, &buflen, strlen(shell) + 1)) == NULL)
	    return NSS_STATUS_TRYAGAIN;

	strcpy(p->pw_shell, shell);

	write_entry(PASSWD_FILE, p);

	return NSS_STATUS_SUCCESS;
    }
    return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_aad_getspnam_r(const char *name, struct spwd *s,
				    char *buffer, size_t buflen,
				    int *errnop)
{
    (void) (errnop);		/* unused-parameter */

    /* If out of memory */
    if ((s->sp_namp =
	 get_static(&buffer, &buflen, strlen(name) + 1)) == NULL) {
	return NSS_STATUS_TRYAGAIN;
    }

    strcpy(s->sp_namp, name);

    if ((s->sp_pwdp =
	 get_static(&buffer, &buflen, MAX_PASSWD_LENGTH + 1)) == NULL) {
	return NSS_STATUS_TRYAGAIN;
    }

    char *passwd = generate_passwd();
    if (passwd == NULL)
	return NSS_STATUS_TRYAGAIN;

    strcpy(s->sp_pwdp, passwd);

    write_entry(SHADOW_FILE, s);

    s->sp_lstchg = 13571;
    s->sp_min = 0;
    s->sp_max = 99999;
    s->sp_warn = 7;

    return NSS_STATUS_SUCCESS;
}
