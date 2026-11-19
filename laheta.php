<?php
/**
 * Päijät-Puu Oy – yhteydenottolomakkeen lähetys sähköpostiin.
 *
 * Lomake (index.html) lähettää tiedot tähän tiedostoon POST-pyynnöllä.
 * Skripti tarkistaa tiedot, lähettää viestin sähköpostiin ja ohjaa
 * käyttäjän takaisin sivulle, jossa näytetään onnistumis- tai virheilmoitus.
 *
 * Vaatimukset: PHP 7.4 tai uudempi ja palvelimen mail()-tuki.
 *
 * Suojaukset:
 *  - vain POST-pyynnöt hyväksytään
 *  - pyynnön on tultava samalta sivustolta (Origin/Referer-tarkistus)
 *  - piilokenttä (honeypot) pysäyttää yksinkertaiset roskapostibotit
 *  - lähetysmäärä rajoitettu IP-osoitetta kohden
 *  - kenttien pituudet rajoitettu ja sähköpostiosoite validoitu
 *  - otsakkeisiin ei päästetä rivinvaihtoja (header injection -suoja)
 *  - käyttäjän syötettä ei koskaan tulosteta sivulle
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// Asetukset
// ---------------------------------------------------------------------------

// Osoite, johon yhteydenotot toimitetaan.
const VASTAANOTTAJA = 'matti.jarvinen@paijat-puu.fi';

// Lähettäjäosoite: sama kuin yhteystiedoissa.
const LAHETTAJA = 'matti.jarvinen@paijat-puu.fi';

// Sivu, jolle käyttäjä ohjataan lähetyksen jälkeen.
const PALUUSIVU = 'index.html';

// Lähetysraja: enintään näin monta viestiä samasta IP-osoitteesta tunnissa.
const MAKS_VIESTIT_TUNNISSA = 5;

// Kenttien enimmäispituudet merkkeinä.
const MAKS_NIMI = 100;
const MAKS_SAHKOPOSTI = 254;
const MAKS_VIESTI = 5000;

// ---------------------------------------------------------------------------

date_default_timezone_set('Europe/Helsinki');

/** Ohjaa takaisin lomakkeelle ja lopettaa skriptin. */
function palaa(string $tila): void
{
    header('Location: ' . PALUUSIVU . '?tila=' . rawurlencode($tila) . '#yhteys', true, 303);
    exit;
}

/** Hakee POST-kentän merkkijonona, poistaa ohjausmerkit ja ylimääräiset välilyönnit. */
function kentta(string $nimi, bool $monirivinen = false): string
{
    $arvo = $_POST[$nimi] ?? '';
    if (!is_string($arvo)) {
        return '';
    }
    // Poistetaan ohjausmerkit. Monirivisessä kentässä sallitaan rivinvaihdot ja sarkain.
    $kuvio = $monirivinen ? '/[^\P{C}\n\t]/u' : '/\p{C}/u';
    $puhdas = preg_replace($kuvio, '', str_replace("\r\n", "\n", $arvo));
    return trim($puhdas ?? '');
}

/** Pituus merkkeinä (myös ilman mbstring-laajennusta). */
function pituus(string $s): int
{
    return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : (int) preg_match_all('/./us', $s);
}

/** Koodaa otsakkeen UTF-8-muotoon, jotta ääkköset näkyvät oikein. */
function otsake(string $s): string
{
    return '=?UTF-8?B?' . base64_encode($s) . '?=';
}

/** Tarkistaa, että pyyntö tuli tältä samalta sivustolta. */
function samaSivusto(): bool
{
    $isanta = $_SERVER['HTTP_HOST'] ?? '';
    $lahde = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
    if ($isanta === '' || $lahde === '') {
        // Jotkin selaimet tai tietosuoja-asetukset jättävät molemmat pois.
        // Ei estetä, muut suojaukset hoitavat tämän tapauksen.
        return true;
    }
    $lahdeIsanta = parse_url($lahde, PHP_URL_HOST);
    $omaIsanta = parse_url('http://' . $isanta, PHP_URL_HOST);
    return is_string($lahdeIsanta) && strcasecmp($lahdeIsanta, (string) $omaIsanta) === 0;
}

/**
 * Rajoittaa lähetyksiä IP-osoitetta kohden. Tiedot tallennetaan väliaikaiskansioon
 * tiivisteenä, joten IP-osoitteita ei tallenneta selväkielisinä.
 * Palauttaa false, jos raja on ylitetty.
 */
function rajoitaLahetyksia(): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'tuntematon';
    $kansio = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'paijatpuu_lomake';
    if (!is_dir($kansio) && !@mkdir($kansio, 0700, true) && !is_dir($kansio)) {
        return true; // Jos kansiota ei voi luoda, ei estetä lähetystä.
    }
    $tiedosto = $kansio . DIRECTORY_SEPARATOR . hash('sha256', $ip . __FILE__) . '.json';
    $nyt = time();

    $kahva = @fopen($tiedosto, 'c+');
    if ($kahva === false) {
        return true;
    }
    flock($kahva, LOCK_EX);
    $sisalto = stream_get_contents($kahva);
    $ajat = json_decode($sisalto ?: '[]', true);
    $ajat = array_values(array_filter(
        is_array($ajat) ? $ajat : [],
        static fn($t) => is_int($t) && $t > $nyt - 3600
    ));

    $sallittu = count($ajat) < MAKS_VIESTIT_TUNNISSA;
    if ($sallittu) {
        $ajat[] = $nyt;
    }
    ftruncate($kahva, 0);
    rewind($kahva);
    fwrite($kahva, json_encode($ajat));
    flock($kahva, LOCK_UN);
    fclose($kahva);

    return $sallittu;
}

// ---------------------------------------------------------------------------
// Käsittely
// ---------------------------------------------------------------------------

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST', true, 405);
    exit('Sallittu vain POST-pyyntö.');
}

if (!samaSivusto()) {
    palaa('virhe');
}

// Piilokenttä: oikea käyttäjä ei näe sitä, botit täyttävät sen.
// Botille näytetään onnistuminen, jotta se ei yritä uudelleen.
if (kentta('kotisivu') !== '') {
    palaa('ok');
}

$nimi = kentta('nimi');
$sahkoposti = kentta('sahkoposti');
$viesti = kentta('viesti', true);

if (
    $nimi === '' || $sahkoposti === '' || $viesti === ''
    || pituus($nimi) > MAKS_NIMI
    || pituus($sahkoposti) > MAKS_SAHKOPOSTI
    || pituus($viesti) > MAKS_VIESTI
    || filter_var($sahkoposti, FILTER_VALIDATE_EMAIL) === false
) {
    palaa('puutteellinen');
}

if (!rajoitaLahetyksia()) {
    palaa('liikaa');
}

$aihe = 'Yhteydenotto verkkosivuilta: ' . $nimi;

$runko = "Uusi yhteydenotto Päijät-Puun verkkosivujen lomakkeelta.\n\n"
    . "Nimi: {$nimi}\n"
    . "Sähköposti: {$sahkoposti}\n"
    . 'Lähetetty: ' . date('j.n.Y \k\l\o H.i') . "\n\n"
    . "Viesti:\n{$viesti}\n\n"
    . "--\nVastaa tähän viestiin, niin vastaus menee suoraan lähettäjälle.\n";

// Rivinvaihdot normalisoidaan sähköpostin vaatimaan muotoon.
$runko = str_replace("\n", "\r\n", $runko);

$otsakkeet = [
    'From' => otsake('Päijät-Puu verkkosivut') . ' <' . LAHETTAJA . '>',
    'Reply-To' => otsake($nimi) . ' <' . $sahkoposti . '>',
    'MIME-Version' => '1.0',
    'Content-Type' => 'text/plain; charset=UTF-8',
    'Content-Transfer-Encoding' => '8bit',
    'X-Mailer' => 'PHP',
];

$lahetetty = mail(VASTAANOTTAJA, otsake($aihe), $runko, $otsakkeet, '-f' . LAHETTAJA);

if (!$lahetetty) {
    // Osa webhotelleista ei salli -f-parametria; yritetään kerran ilman sitä.
    $lahetetty = mail(VASTAANOTTAJA, otsake($aihe), $runko, $otsakkeet);
}

if (!$lahetetty) {
    error_log('Päijät-Puu lomake: sähköpostin lähetys epäonnistui.');
    palaa('virhe');
}

palaa('ok');
