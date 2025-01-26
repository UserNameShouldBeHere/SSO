create database auth;

\c auth;

create table if not exists permission (
    level integer primary key,
    name text unique not null,
    plist text[]
);

create table if not exists users (
    id integer primary key generated always as identity,
    uuid uuid unique default gen_random_uuid() not null,
    name text check(length(name) >= 3 and length(name) < 64) not null,
    email text check(length(email) >= 3 and length(email) < 320) unique not null,
    password text not null,
    permissions_level integer default 1, -- can be 0 or null (maybe it will be the same)
    registered_at timestamp default now() not null,
    foreign key(permissions_level) references permission(level) on delete set null
);

insert into permission(level, name) values (0, 'none'), (1, 'guest');
-- insert into permission(level, name, plist) values (2, 'admin', array['user:getall']);
-- insert into permission(level, name, plist) values (3, 'owner', array['user:getall','user:remove','user:ban','user:unban']);

