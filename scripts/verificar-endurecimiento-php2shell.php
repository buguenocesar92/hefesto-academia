<?php

declare(strict_types=1);

/**
 * CANDADO: CVE-2026-109618 / CVE-2026-109619 (PHP2Shell, @@FECHA@@).
 *
 * Este repo no tiene framework de pruebas: es una imagen de Moodle con Apache y
 * mod_php, sin `composer.json` ni suite de PHPUnit. El candado es este script,
 * que se puede correr sin instalar nada:
 *
 *     php scripts/verificar-endurecimiento-php2shell.php
 *
 * Y tambien se corre DENTRO de la imagen, como puerta del build (ver el
 * Dockerfile), para que una imagen sin el endurecimiento no se pueda construir:
 *
 *     php scripts/verificar-endurecimiento-php2shell.php --imagen
 *
 * QUE COMPRUEBA
 * -------------
 *   1. Que la base de la imagen use una version de PHP PARCHEADA (las
 *      parcheadas son 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
 *   2. Que el ini de endurecimiento apague `session.upload_progress.enabled`,
 *      que es la via CONFIRMADA de CVE-2026-109619.
 *   3. Que la etapa final del Dockerfile copie el ini a `conf.d` y el archivo de
 *      Apache a `conf-available/`, y que lo habilite con `a2enconf`.
 *   4. Que Apache recicle los hijos cada 100 peticiones.
 *   5. Que la etapa final actualice el sistema base.
 *   6. Que NADA en el repo vuelva a encender `session.upload_progress.enabled`.
 *   7. Que la base de la imagen este por encima de la version parcheada de
 *      CVE-2026-126714 (8.3.37 en la serie 8.3), que es mas alta que la de
 *      PHP2Shell, y que el ini registre la version con la que se construyo.
 *   8. Que el ini de mitigacion de sesiones nativas exista con sus cuatro
 *      directivas y que la etapa final lo copie a conf.d.
 *
 * SALE CON CODIGO 0 SI TODO ESTA BIEN, Y CON CODIGO 1 SI ALGO FALLA.
 */

const VERSION_MINIMA = '8.3.37';
const SERIE = '8.3';

const DOCKERFILE = 'Dockerfile';
const INI = 'docker/99-php2shell-hardening.ini';
const APACHE = 'docker/zz-php2shell-apache.conf';

// CVE-2026-126714 (GHSA-fm2m-fjf5-v3cp): el save handler "files" de
// ext-session reescribe el archivo de sesion sin truncarlo.
const INI_SESIONES = 'docker/php/99-security-cve-2026-126714.ini';
const DIRECTIVAS_SESIONES = [
    'session.upload_progress.enabled = Off',
    'session.upload_progress.cleanup = On',
    'session.serialize_handler = php_serialize',
    'session.use_strict_mode = 1',
];

$fallos = [];

/**
 * @return list<string>
 */
function fallos(): array
{
    global $fallos;

    return $fallos;
}

function anota(string $mensaje): void
{
    global $fallos;

    $fallos[] = $mensaje;
}

function raiz(): string
{
    return dirname(__DIR__);
}

function leer(string $ruta): string
{
    return (string) file_get_contents($ruta);
}

/**
 * El texto del Dockerfile con las continuaciones de linea unidas.
 */
function dockerfileUnido(): string
{
    return (string) preg_replace('/\x5c[ \t]*\n[ \t]*/', ' ', leer(raiz().'/'.DOCKERFILE));
}

/**
 * Las lineas de la ETAPA FINAL del Dockerfile.
 *
 * @return list<string>
 */
function lineasDeLaEtapaFinal(): array
{
    $lineas = array_values(array_filter(
        array_map('trim', explode("\n", dockerfileUnido())),
        fn (string $linea): bool => $linea !== '' && ! str_starts_with($linea, '#'),
    ));

    $ultimoFrom = 0;
    foreach ($lineas as $indice => $linea) {
        if (preg_match('/^FROM\s/i', $linea) === 1) {
            $ultimoFrom = $indice;
        }
    }

    return array_slice($lineas, $ultimoFrom);
}

function comprobarLaVersionDeLaBase(): void
{
    $contenido = leer(raiz().'/'.DOCKERFILE);

    if (preg_match('/^FROM\s+(?:docker\.io\/library\/)?php:(\S+)/mi', $contenido, $coincidencia) !== 1) {
        anota('El Dockerfile no declara una base «FROM php:...».');

        return;
    }

    $tag = $coincidencia[1];

    // La base va fijada por digest: un tag puede mudar entre dos builds sin
    // que nadie lo note, y con el se va el parche de PHP.
    if (! str_contains($tag, '@sha256:')) {
        anota('La base «'.$tag.'» no esta fijada por digest («tag@sha256:...»): el tag puede mudar entre dos builds sin que nadie lo note.');
    }

    // Y tiene que decir la version completa: un tag flotante como
    // «8.3-apache-bookworm» no deja constancia de con que PHP se construyo.
    if (preg_match('/^(\d+\.\d+\.\d+)/', $tag, $version) !== 1) {
        anota('La base «'.$tag.'» no fija la version PHP x.y.z.');

        return;
    }

    if (! str_starts_with($version[1], SERIE.'.')) {
        anota('La base «'.$tag.'» no es de la serie '.SERIE.', que es la que tiene la version parcheada ('.VERSION_MINIMA.').');

        return;
    }

    if (version_compare($version[1], VERSION_MINIMA, '<')) {
        anota('La base «'.$tag.'» esta por debajo de la version parcheada ('.VERSION_MINIMA.') de la serie '.SERIE.'.');
    }
}

function comprobarLaVersionVerificada(): void
{
    $ini = leer(raiz().'/'.INI);

    if (preg_match('/PHP verificado:\s*(\d+\.\d+\.\d+)/', $ini, $coincidencia) !== 1) {
        anota(INI.' no deja constancia de la version de PHP con la que se construyo la imagen.');

        return;
    }

    if (version_compare($coincidencia[1], VERSION_MINIMA, '<')) {
        anota('La version de PHP verificada ('.$coincidencia[1].') esta por debajo de la version parcheada ('.VERSION_MINIMA.') de la serie '.SERIE.'.');
    }
}

function comprobarElIni(): void
{
    $ruta = raiz().'/'.INI;

    if (! is_file($ruta)) {
        anota('Falta '.INI.': la imagen queda con los valores de fabrica de PHP.');

        return;
    }

    $valores = parse_ini_file($ruta, false, INI_SCANNER_TYPED);

    if (! is_array($valores)) {
        anota(INI.' no se puede leer como ini.');

        return;
    }

    if (! array_key_exists('session.upload_progress.enabled', $valores)) {
        anota(INI.' no fija «session.upload_progress.enabled»: es la via CONFIRMADA del UAF de CVE-2026-109619.');

        return;
    }

    if ($valores['session.upload_progress.enabled']) {
        anota(INI.' deja «session.upload_progress.enabled» encendido: PHP lo trae en On por omision.');
    }
}

function comprobarLasCopias(): void
{
    $etapa = implode("\n", lineasDeLaEtapaFinal());

    if (preg_match('#^COPY\s+'.preg_quote(INI, '#').'\s+/usr/local/etc/php/conf\.d/[\w.-]+\.ini$#m', $etapa) !== 1) {
        anota('La etapa final del Dockerfile no copia '.INI.' a /usr/local/etc/php/conf.d/: el endurecimiento no llega al contenedor.');
    }

    if (preg_match('#^COPY\s+'.preg_quote(INI_SESIONES, '#').'\s+/usr/local/etc/php/conf\.d/[\w.-]+\.ini$#m', $etapa) !== 1) {
        anota('La etapa final del Dockerfile no copia '.INI_SESIONES.' a /usr/local/etc/php/conf.d/: la mitigacion de CVE-2026-126714 no llega al contenedor.');
    }

    if (preg_match('#^COPY\s+'.preg_quote(APACHE, '#').'\s+/etc/apache2/conf-available/[\w.-]+\.conf$#m', $etapa) !== 1) {
        anota('La etapa final del Dockerfile no copia '.APACHE.' a /etc/apache2/conf-available/: el reciclaje de los hijos no llega al contenedor.');
    }

    if (str_contains($etapa, 'a2enconf zz-php2shell-hardening') === false) {
        anota('El Dockerfile no habilita el archivo de Apache con «a2enconf zz-php2shell-hardening».');
    }
}

/**
 * El ini de mitigacion de CVE-2026-126714: debe existir y fijar sus cuatro
 * directivas, tal cual (mismo formato que el verificador externo del parche).
 */
function comprobarElIniDeLasSesiones(): void
{
    $ruta = raiz().'/'.INI_SESIONES;

    if (! is_file($ruta)) {
        anota('Falta '.INI_SESIONES.': la imagen queda con los valores de fabrica de PHP.');

        return;
    }

    $contenido = leer($ruta);

    foreach (DIRECTIVAS_SESIONES as $directiva) {
        if (preg_match('/^'.preg_quote($directiva, '/').'$/m', $contenido) !== 1) {
            anota(INI_SESIONES.' no fija la directiva exacta «'.$directiva.'».');
        }
    }
}

function comprobarElReciclajeDeApache(): void
{
    $ruta = raiz().'/'.APACHE;

    if (! is_file($ruta)) {
        anota('Falta '.APACHE.'.');

        return;
    }

    if (preg_match('/^\s*MaxRequestsPerChild\s+100\s*$/m', leer($ruta)) !== 1) {
        anota(APACHE.' no fija «MaxRequestsPerChild 100»: sin el, Apache usa 1000 peticiones por hijo.');
    }
}

function comprobarLaActualizacionDelSistema(): void
{
    $etapa = implode("\n", lineasDeLaEtapaFinal());

    if (preg_match('/apt-get\s+upgrade|apk\s+update\s*&&\s*apk\s+upgrade/', $etapa) !== 1) {
        anota('La etapa final del Dockerfile no actualiza el sistema base («apt-get upgrade»): las librerias del sistema quedan en la version vulnerable.');
    }
}

function comprobarQueNadaEnciendeElUploadProgress(): void
{
    $archivos = [raiz().'/'.DOCKERFILE];

    $iterador = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(raiz(), FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterador as $archivo) {
        $ruta = $archivo->getPathname();

        if (str_contains($ruta, '/vendor/') || str_contains($ruta, '/node_modules/')) {
            continue;
        }

        if (in_array(strtolower($archivo->getExtension()), ['ini', 'sh'], true)) {
            $archivos[] = $ruta;
        }
    }

    foreach ($archivos as $archivo) {
        if (realpath($archivo) === realpath(raiz().'/'.INI)) {
            continue;
        }

        foreach (explode("\n", leer($archivo)) as $linea) {
            $linea = trim($linea);

            if (str_starts_with($linea, '#') || str_starts_with($linea, ';')) {
                continue;
            }

            if (preg_match('/session\.upload_progress\.enabled\s*=\s*["\']?(1|on|true|yes)\b/i', $linea) === 1) {
                anota(basename($archivo).' vuelve a encender session.upload_progress.enabled: «'.$linea.'»');
            }
        }
    }
}

/**
 * Comprobaciones dentro de la imagen ya construida.
 */
function comprobarLaImagen(): void
{
    $ini = '/usr/local/etc/php/conf.d/99-php2shell-hardening.ini';

    if (! is_file($ini)) {
        anota('La imagen no tiene '.$ini.'.');

        return;
    }

    $valores = parse_ini_file($ini, false, INI_SCANNER_TYPED);
    if (! is_array($valores) || ($valores['session.upload_progress.enabled'] ?? null) !== false) {
        anota('En la imagen, «session.upload_progress.enabled» no esta en Off.');
    }

    $apache = '/etc/apache2/conf-available/zz-php2shell-hardening.conf';

    if (! is_file($apache)) {
        anota('La imagen no tiene '.$apache.'.');

        return;
    }

    if (preg_match('/^\s*MaxRequestsPerChild\s+100\s*$/m', leer($apache)) !== 1) {
        anota('En la imagen, «MaxRequestsPerChild 100» no esta.');
    }

    if (! is_link('/etc/apache2/conf-enabled/zz-php2shell-hardening.conf')
        && ! is_file('/etc/apache2/conf-enabled/zz-php2shell-hardening.conf')) {
        anota('En la imagen, el archivo de Apache no esta habilitado en conf-enabled/.');
    }

    // CVE-2026-126714: el ini de mitigacion tiene que estar en la imagen, y sus
    // valores tienen que ser los EFECTIVOS: otro .ini de conf.d los puede pisar.
    $iniSesiones = '/usr/local/etc/php/conf.d/99-security-cve-2026-126714.ini';

    if (! is_file($iniSesiones)) {
        anota('La imagen no tiene '.$iniSesiones.'.');

        return;
    }

    $efectivos = [
        'session.upload_progress.enabled' => ['', '0'],
        'session.upload_progress.cleanup' => ['1'],
        'session.serialize_handler' => ['php_serialize'],
        'session.use_strict_mode' => ['1'],
    ];

    foreach ($efectivos as $directiva => $valores) {
        $valor = (string) ini_get($directiva);

        if (! in_array($valor, $valores, true)) {
            anota('En la imagen, «'.$directiva.'» vale «'.$valor.'», y deberia valer '.implode(' o ', $valores).'.');
        }
    }
}

$modoImagen = in_array('--imagen', $argv, true);

if ($modoImagen) {
    comprobarLaImagen();
} else {
    comprobarLaVersionDeLaBase();
    comprobarLaVersionVerificada();
    comprobarElIni();
    comprobarElIniDeLasSesiones();
    comprobarLasCopias();
    comprobarElReciclajeDeApache();
    comprobarLaActualizacionDelSistema();
    comprobarQueNadaEnciendeElUploadProgress();
}

if (fallos() !== []) {
    fwrite(STDERR, "CANDADO PHP2Shell: FALLA\n");
    foreach (fallos() as $mensaje) {
        fwrite(STDERR, '  - '.$mensaje."\n");
    }

    exit(1);
}

fwrite(STDOUT, 'CANDADO PHP2Shell: OK ('.($modoImagen ? 'imagen' : 'repo').")\n");

exit(0);
