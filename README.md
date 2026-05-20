<h1 align="center">LYNX</h1>

<p align="center">
  <em>stealth tcp port scanner</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-in_development-B8860B?style=flat"/>
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-3DA639?style=flat"/>
</p>

---

## > Overview

**Lynx** is a stealth-oriented TCP port scanning engine designed for low-noise reconnaissance and network surface mapping.

The project focuses on packet-level scanning techniques using crafted TCP packets and flag manipulation to identify exposed services while reducing detection visibility.

Lynx was built for:

* Network reconnaissance research
* Controlled offensive security testing
* Service exposure analysis
* Low-noise TCP scanning experiments

---

## > Features

* TCP-based port scanning
* Crafted packet generation
* TCP flag manipulation techniques
* Stealth-oriented reconnaissance workflows

---

## > Installation

```bash
git clone https://github.com/0xf0xy/Lynx.git
cd Lynx
sudo pip install .
```

Verify installation:

```bash
lynx -h
```

---

## > Requirements

* Python 3.10+
* Linux system

---

## > Project Status

Lynx is currently in active development.  
Features, scanning techniques, and internal behavior may change during development.

---

## > Warning

This project is provided for **educational and research purposes only**.  
Only scan systems and networks you own or are explicitly authorized to test.  
You are responsible for any misuse of this software.

---

<p align="center">
  <a href="https://github.com/0xf0xy"><b>0xf0xy</b></a> • 
  <a href="./LICENSE"><b>MIT License</b></a>
</p>
