*We got our hands on a confidential case file from some self-declared "black hat hackers"... it looks like they have a secret invite code.*

**Difficutly:** Easy

#blue #QR

We are given a PDF from the black hat hackers. A QR code is shown,  but it is partially obscured by a red "!" icon. I tried scanning it as is, since through research I learned that QR codes user Reed-Solomon error correction and can sometimes still be read even if the entire barcode is not visible. In this case it was obscured too much to be scanable.

I tried saving the image of the obscured QR code from PDF and upon inspection, only the icon covering the code was saved as a png with a transparent background. I next saved the image of the pdf, clicking in an area far away from the red icon. I got an image of the whole pdf, including the QR code without the icon, which was just layered on top of this image.

The flag is received by scanning the unobscured QR code.