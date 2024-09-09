from django import forms

class EmailUploadForm(forms.Form):
    email_file = forms.FileField(label='Select an EML file')
