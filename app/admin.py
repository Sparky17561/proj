from django.contrib import admin
from .models import EmailFeedback

@admin.register(EmailFeedback)
class EmailFeedbackAdmin(admin.ModelAdmin):
    list_display = ('email', 'proof')  # Display fields in list view
    search_fields = ('email',)  # Add search capability for email field
    list_filter = ('email',)  # Add filter capability for email field

    # Customize the form layout
    fieldsets = (
        (None, {
            'fields': ('email', 'proof')
        }),
        # Add more sections if needed
    )

    # Customize how the list view looks (optional)
    ordering = ('email',)  # Order list view by email
    # Add any additional configurations as needed
