# Evilginx 3.0
```
- git clone https://github.com/fluxxset/evilginx2.git
- cd evilginx2
- ./evilginx2 # and exit
- nano /root/.evilginx/config.json ## add chatid and teletoken and save and exit
- ./evilginx2
```
---
Big Thanks to [kgretzky](https://github.com/kgretzky/) for Creating such great tool  
---

**Evilginx** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.

This tool is a successor to [Evilginx](https://github.com/kgretzky/evilginx), released in 2017, which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website.
Present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.

<p align="center">
  <img alt="Screenshot" src="https://raw.githubusercontent.com/kgretzky/evilginx2/master/media/img/screen.png" height="320" />
</p>

---
This has been modified to only send valid sessions, no empty logs, and will include the cookies in a randomly named TXT file. 📂✅🍪

![image (4)](https://github.com/user-attachments/assets/a102ecd7-e342-44c4-bff5-3004d16c0df4)
---

## Disclaimer

I am very much aware that Evilginx can be used for nefarious purposes. This work is merely a demonstration of what adept attackers can do. It is the defender's responsibility to take such attacks into consideration and find ways to protect their users against this type of phishing attacks. Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.


---
## 🧑‍🏫 Evilginx Training Course

> 🔥 *Already mastering Evilginx? Level up with my complete [Evilginx Training Course](https://shop.fluxxset.com/product/evilginx-training-course/). Check it out!*

![Evilginx Training Course Banner](http://shop.fluxxset.com/wp-content/uploads/2024/08/Evilginx_course.png)
<!-- ## 🧑‍🏫 Evilginx Training Course

Ready to become an Evilginx master? Check out my [Complete Evilginx Training Course](https://shop.fluxxset.com/product/evilginx-training-course/)! It covers everything from setting up Evilginx, creating advanced phishlets, to deploying custom plugins with Python. It's packed with *tips, tricks*, and *real-world examples*. -->

---
