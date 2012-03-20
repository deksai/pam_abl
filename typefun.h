#ifndef TYPEFUN_H
#define TYPEFUN_H

#include <time.h>

typedef enum {
    HOST_BLOCKED = 0x01,
    USER_BLOCKED = 0x02,
    BOTH_BLOCKED = 0x03,
    AUTH_FAILED  = 0x04
} BlockReason;

typedef enum {
    BLOCKED = 0x01,
    CLEAR = 0x02
} BlockState;

typedef struct AuthAttempt {
    BlockReason m_reason;
    time_t m_time;
    char *m_userOrHost;
    char *m_service;
} AuthAttempt;

typedef struct AuthState {
//    BlockState state;
//    AuthAttempt *attempts;
//    size_t size;
    void   *m_data;
    void   *m_current; //a pointer to the first field of the next AuthAttempt
    size_t  m_size; //the size of the memory block pointed to by m_data
    size_t  m_usedSize; //how many bytes of m_data are used
} AuthState;

int  createEmptyState(BlockState blockState, AuthState **state);
int  createAuthState(void *data, size_t size, AuthState **state);
BlockState  getState(AuthState *state);
int  setState(AuthState *state, BlockState blockState);
unsigned int getNofAttempts(AuthState *state);
int  firstAttempt(AuthState *state);
int  nextAttempt(AuthState *state, AuthAttempt *attempt);
void destroyAuthState(AuthState *state);
int  addAttempt(AuthState *state, BlockReason reason, time_t time, const char *userOrHost, const char *service, unsigned int lowerLimit, unsigned int upperLimit);
void purgeAuthState(AuthState *state, time_t purgeTime);

#endif
