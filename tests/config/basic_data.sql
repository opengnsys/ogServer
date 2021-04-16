
DELETE FROM centros;
INSERT INTO centros (
  idcentro, nombrecentro, identidad, comentarios, directorio)
VALUES
(1, 'Center', 1, '', '');

DELETE FROM aulas;
INSERT INTO aulas (
  nombreaula, idcentro, urlfoto, grupoid,
  ubicacion, puestos, modomul, ipmul,
  pormul, velmul, router, netmask, ntp,
  dns, proxy, modp2p, timep2p
)
VALUES
  (
    'Room', 1, 'aula.jpg', 0, 'Test room.',
    5, 2, '239.194.2.11', 9000, 70, '192.168.56.1',
    '255.255.255.0', '', '', '', 'peer',
    30
  );

DELETE FROM ordenadores;
INSERT INTO ordenadores (
  nombreordenador, ip, mac, idaula, idrepositorio,
  idperfilhard, idmenu, idproautoexec,
  grupoid, router, mascara, arranque,
  netiface, netdriver, fotoord
)
VALUES
  (
    'pc2', '192.168.2.1', '0800270E6501',
    1, 1, 0, 0, 0, 0, '192.168.56.1', '255.255.255.0',
    '00unknown', 'eth0', 'generic', 'fotoordenador.gif'
  ),
  (
    'pc2', '192.168.2.2', '0800270E6502',
    1, 1, 0, 0, 0, 0, '192.168.56.1', '255.255.255.0',
    '00unknown', 'eth0', 'generic', 'fotoordenador.gif'
  );

