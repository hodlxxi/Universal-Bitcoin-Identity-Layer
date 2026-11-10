"""Private device routes for the explicit Social V2 entrypoint."""

from app.blueprints.internal_social_messaging_device import internal_social_messaging_device_bp
from app.blueprints.internal_social_messaging_device_binding_authorization import (
    internal_social_messaging_device_binding_authorization_bp,
)
from app.blueprints.internal_social_messaging_recipient import internal_social_messaging_recipient_bp
from app.services.privacy_full_directory_internal_delivery import configured_internal_delivery_runtime
from app.services.social_messaging_device_internal_delivery import configure_messaging_device_internal_delivery
from app.services.social_messaging_device_binding_authorization_runtime import (
    configure_messaging_device_binding_authorization,
)
from app.services.social_messaging_recipient_runtime_configuration import (
    configure_messaging_recipient_internal_delivery,
)


def install_private_messaging(app, cfg):
    device = configure_messaging_device_internal_delivery(app, cfg)
    binding = configure_messaging_device_binding_authorization(app, cfg)
    recipient = configure_messaging_recipient_internal_delivery(
        app, cfg, privacy_directory_runtime=configured_internal_delivery_runtime(app)
    )
    for enabled, blueprint in (
        (device, internal_social_messaging_device_bp),
        (binding, internal_social_messaging_device_binding_authorization_bp),
        (recipient, internal_social_messaging_recipient_bp),
    ):
        if enabled:
            app.register_blueprint(blueprint)
