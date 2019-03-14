<?php

define("COLOR_DEFAULT", 1);
define("COLOR_BLACK", 2);
define("COLOR_RED", 3);
define("COLOR_GREEN", 4);
define("COLOR_YELLOW", 5);
define("COLOR_BLUE", 6);
define("COLOR_MAGENTA", 7);
define("COLOR_CYAN", 8);
define("COLOR_LIGHT_GRAY", 9);
define("COLOR_DARK_GREY", 10);
define("COLOR_LIGHT_RED", 11);
define("COLOR_LIGHT_GREEN", 12);
define("COLOR_LIGHT_YELLOW", 13);
define("COLOR_LIGHT_BLUE", 14);
define("COLOR_LIGHT_MAGENTA", 15);
define("COLOR_LIGHT_CYAN", 16);
define("COLOR_WHITE", 17);

function set_color($col) {
  $r = chr(0x1b);
  $r .= chr(0x5b);

  switch($col) {
    case COLOR_BLACK:
      $r .= "30";
      break;
    case COLOR_RED:
      $r .= "31";
      break;
    case COLOR_GREEN:
      $r .= "32";
      break;
    case COLOR_YELLOW:
      $r .= "33";
      break;
    case COLOR_BLUE:
      $r .= "34";
      break;
    case COLOR_MAGENTA:
      $r .= "35";
      break;
    case COLOR_CYAN:
      $r .= "36";
      break;
    case COLOR_LIGHT_GRAY:
      $r .= "37";
      break;
    case COLOR_DARK_GREY:
      $r .= "90";
      break;
    case COLOR_LIGHT_RED:
      $r .= "91";
      break;
    case COLOR_LIGHT_GREEN:
      $r .= "92";
      break;
    case COLOR_LIGHT_YELLOW:
      $r .= "93";
      break;
    case COLOR_LIGHT_BLUE:
      $r .= "94";
      break;
    case COLOR_LIGHT_MAGENTA:
      $r .= "95";
      break;
    case COLOR_LIGHT_CYAN:
      $r .= "96";
      break;
    case COLOR_WHITE:
      $r .= "97";
      break;
    default:
      $r .= "39";
  }

  $r .= "m";
  return $r;
}

function set_background($col) {
  $r = chr(0x1b);
  $r .= chr(0x5b);

  switch($col) {
    case COLOR_BLACK:
      $r .= "40";
      break;
    case COLOR_RED:
      $r .= "41";
      break;
    case COLOR_GREEN:
      $r .= "42";
      break;
    case COLOR_YELLOW:
      $r .= "43";
      break;
    case COLOR_BLUE:
      $r .= "44";
      break;
    case COLOR_MAGENTA:
      $r .= "45";
      break;
    case COLOR_CYAN:
      $r .= "46";
      break;
    case COLOR_LIGHT_GRAY:
      $r .= "47";
      break;
    case COLOR_DARK_GREY:
      $r .= "100";
      break;
    case COLOR_LIGHT_RED:
      $r .= "101";
      break;
    case COLOR_LIGHT_GREEN:
      $r .= "102";
      break;
    case COLOR_LIGHT_YELLOW:
      $r .= "103";
      break;
    case COLOR_LIGHT_BLUE:
      $r .= "104";
      break;
    case COLOR_LIGHT_MAGENTA:
      $r .= "105";
      break;
    case COLOR_LIGHT_CYAN:
      $r .= "106";
      break;
    case COLOR_WHITE:
      $r .= "107";
      break;
    default:
      $r .= "49";
  }

  $r .= "m";
  return $r;
}

function text_normal() {
  $r = chr(0x1b);
  $r .= chr(0x5b);
  $r .= chr(0x30);
  $r .= chr(0x6d);
  return $r;
}

function text_bold() {
  $r = chr(0x1b);
  $r .= chr(0x5b);
  $r .= chr(0x31);
  $r .= chr(0x6d);
  return $r;
}

function text_underline() {
  $r = chr(0x1b);
  $r .= chr(0x5b);
  $r .= chr(0x34);
  $r .= chr(0x6d);
  return $r;
}

function clear_screen() {
  $r = text_normal();
  $r .= set_cursor(0, 0);
  $r .= chr(0x1b);
  $r .= chr(0x5b);
  $r .= chr(0x32);
  $r .= chr(0x4a);
  return $r;
}

function set_cursor($x, $y) {
  $r = "";
  $r .= chr(0x1b);
  $r .= chr(0x5b);
  $r .= (string)$y;
  $r .= ";";
  $r .= (string)$x;
  $r .= "f";
  return $r;
}

?>
