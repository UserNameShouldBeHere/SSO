# SSO [![License](https://img.shields.io/github/license/UserNameShouldBeHere/SSO)](https://opensource.org/license/mit) [![Lang](https://img.shields.io/github/languages/top/UserNameShouldBeHere/SSO)]([https://opensource.org/license/mit](https://go.dev/))


## Some info

This project is a simple implementation of SSO written in Go.

There are 2 common roles:
- none (stands for banned users)
- guest (common role for new users)

Additional roles can be added, like:
- admin (admins can manipulate other users)
- owner

And currently available extended permissions:
- user:getall (show the list of other users)
- user:remove (remove other user)
- user:ban (ban user)
- user:unban (unban user)

All these roles can be modified or additional roles can be added in [config file](cmd/config.yml)

## Methods

### For current user:

- SignUp
- SignIn
- Check
- LogoutCurrent
- LogoutAll
- LogoutSession (logout provided session)
- GetUser
- RemoveCurrentUser
- GetAllSessions
- UpdateUserName

### For managment (required specific permissions):

- GetAllUsers
- RemoveUser
- BanUser
- UnBanUser

## Config

#### roles

`roles` field used to predefine roles with permissions. There are 2 roles that are defined in [init.sql](db/init.sql):
- none (for banned user)
- guest (for every new user)

Other roles can be added in this section

#### users

`users` field used to predefine users with roles. For example, define an owner with all permissions to have access to managment methods

#### server

`server` field used to set specific constants like session expiration or flushing interval for expired sessions

## How to run SSO?
1) First setup [config](cmd/config.yml)
2) Then build containers for postgres and sso using `podman build -t postgres -f db/Containerfile db` and `podman build -t sso -f cmd/Containerfile .`
3) Finally start the server using `podman kube play pod.yml`
