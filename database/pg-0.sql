DROP TABLE IF EXISTS pub;
DROP TABLE IF EXISTS sub;
DROP TABLE IF EXISTS packet;
DROP TABLE IF EXISTS confo;

CREATE TABLE IF NOT EXISTS pub (
	pub_id SERIAL PRIMARY KEY,
	latitude REAL NOT NULL,
	longitude REAL NOT NULL,
	altitude REAL NOT NULL,
	orientation REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sub (
	sub_id SERIAL PRIMARY KEY,
	email VARCHAR(64),
	phone VARCHAR(32)
);

CREATE TABLE IF NOT EXISTS packet (
	pub_id INTEGER NOT NULL REFERENCES pub(pub_id),
	id SERIAL PRIMARY KEY,
	created_at TIMESTAMPTZ NOT NULL default current_timestamp,
	saved_at TIMESTAMPTZ NOT NULL default current_timestamp,
	voltage REAL,
	frequency REAL,
	protected boolean NOT NULL
);

CREATE TABLE IF NOT EXISTS confo (
	id SERIAL,
	created_at TIMESTAMPTZ NOT NULL default current_timestamp,
	devicename VARCHAR(32),
	ssid VARCHAR(32),
	PRIMARY KEY (created_at, devicename, ssid)
);

CREATE INDEX sub_index ON coordinate(user_id);
CREATE INDEX packet_index ON packet(id);
