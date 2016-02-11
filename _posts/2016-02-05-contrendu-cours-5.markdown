---
layout: post
title:  "Cours #5 - Contrendu"
date:   2016-02-05 17:42:09 -0500
categories: contrendu
---

Pour aider à mieux voir la topologie du réseau, un graphique représentant le poste sur lequel notre logiciel roule, et tous les autres postes détectés du réseau est de mise. En premier lieu, nous avons recherché les meilleures librairies qui pourraient nous aider en python à illustrer le chemin qu’un paquet emprunte. Nous avons trouvé une librairie nommée **NetworkX** qui nous permettait de faire des schémas d’images. Malgré cela, NetworkX n’est pas très complet et ne faisait qu’un graphique très basique. Nous avons alors été vers une autre librairie nommée **Mayavi** qui nous permettrait de faire des graphiques 3d ou encore des graphiques plus complets et élaborés. Nous avons donc essayé avec cette librairie externe de faire un graphique comprenant seulement 3 postes pour voir à quoi cela ressemblerait. Le résultat était un graphique qui n’était pas vraiment ce que nous recherchions, il n’illustrait pas le chemin pris par le paquet pour aller à un poste, mais plutôt seulement les postes qu’il pouvait atteindre. Raphaël Doré a eu une très bonne idée, il a regardé si une fonction pour faire des graphiques n’existerait pas dans Scapy (la librairie que nous utilisions déjà). Comme de fait, Raphaël avait raison et une fonction graphe existe bel et bien dans la libraire Scapy. De plus, les graphiques faits par Scapy représentent déjà beaucoup mieux ce que nous recherchons. Nous allons donc partir des graphiques de Scapy comme base et ajouter ce que nous y désirons. Les graphiques de la topologie du réseau seront parfaits et complets sous peu.

Le scanneur n'est toujours pas complété, mais il est fonctionnel. Ça va être le temps bientôt de trouver une manière de déterminer le système d'exploitation roulant sur la machine d'un hôte qui a été détecté par le scanneur (on a besoin de ces informations pour détecter des vulnérabilitées)...
