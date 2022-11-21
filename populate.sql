DELETE FROM auth;
DELETE FROM cookie;
DELETE FROM miniurl;
INSERT INTO auth (username,password) VALUES ('bob','letemin');
INSERT INTO miniurl (hash,url,count) VALUES ('aaa','https://google.com',0);
