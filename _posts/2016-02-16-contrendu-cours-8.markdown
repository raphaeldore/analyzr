---
layout: post
title:  "Cours #8 - Contrendu"
date:   2016-02-16 12:33:29 -0500
categories: contrendu
---

Aujourd’hui on s’est lancé dans le module d’identification de l’OS. C’était amusant, mais surtout frustrant en même temps. Pour identifier le système d’opération d’une machine, on utilise une base de données de signatures de paquets (car oui chaque système d’opération a sa propre manière de créer des paquets. Ex. : un paquet ICMP sur Windows va avoir un TTL de 68, tandis que sur Linux ça va être 120). Scapy n’est pas très bien documenté, alors on a dû se battre constamment pour trouver les propriétés des paquets qu’il nous faut pour comparer les valeurs des propriétés d’un paquet à la base de données de signatures. On n’a pas terminé, mais ça s’approche.
