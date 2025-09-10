from django.db import models

class DeviceStatus(models.Model):
    device = models.CharField(max_length=50, primary_key=True)
    certificate_status = models.BooleanField(default=True)
    key_status = models.BooleanField(default=True)
    mtls_status = models.BooleanField(default=True)
    mitm_status = models.BooleanField(default=True)
    revoked = models.BooleanField(default=False)
    latency = models.FloatField(null=True)
    valid_from = models.DateTimeField(null=True)
    valid_to = models.DateTimeField(null=True)
    last_checked = models.DateTimeField(null=True)

    def __str__(self):
        return self.device