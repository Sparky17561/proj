from django.db import models

class EmailFeedback(models.Model):
    email = models.EmailField(max_length=254)
    proof = models.TextField()

    def __str__(self):
        return self.email
