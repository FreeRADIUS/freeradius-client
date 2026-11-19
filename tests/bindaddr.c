/* Exercise retained configuration addresses while temporary lookup results
 * are released. Run this test under a leak checker to verify cleanup too. */
#include <config.h>
#include <includes.h>
#include <freeradius-client.h>

static int check_address(rc_handle *rh, int family)
{
	struct in_addr address4;
	struct in6_addr address6;
	struct sockaddr_storage *stored = &rh->own_bind_addr;

	if (!rh->own_bind_addr_set || stored->ss_family != family)
		return 0;
	if (family == AF_INET) {
		inet_pton(AF_INET, "127.0.0.1", &address4);
		return memcmp(&((struct sockaddr_in *)stored)->sin_addr,
		              &address4, sizeof(address4)) == 0;
	}
	inet_pton(AF_INET6, "::1", &address6);
	return memcmp(&((struct sockaddr_in6 *)stored)->sin6_addr,
	              &address6, sizeof(address6)) == 0;
}

int main(void)
{
	rc_handle *handles[64] = { NULL };
	unsigned i;
	int ok = 1;

	for (i = 0; i < 64; ++i) {
		handles[i] = rc_new();
		if (!handles[i]) {
			ok = 0;
			break;
		}
		handles[i] = rc_config_init(handles[i]);
		if (!handles[i]) {
			ok = 0;
			break;
		}
		if (rc_add_config(handles[i], "bindaddr", i % 2 ? "::1" : "127.0.0.1",
		                  __FILE__, __LINE__) != 0) {
			ok = 0;
			break;
		}
	}
	/* Later lookups can reuse the temporary resolver allocation. Every
	 * retained handle must still contain its own copied IPv4/IPv6 address. */
	for (i = 0; i < 64; ++i) {
		if (handles[i]) {
			if (!check_address(handles[i], i % 2 ? AF_INET6 : AF_INET))
				ok = 0;
			rc_destroy(handles[i]);
		}
	}
	if (!ok)
		fprintf(stderr, "retained bind address was not preserved\n");
	return ok ? 0 : 1;
}
