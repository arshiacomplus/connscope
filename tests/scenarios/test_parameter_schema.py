
import pytest

from connscope.scenarios import (
    ParameterDefinition,
    ParameterType,
    ParameterVariant,
)

def test_string_parameter_validation():
    p = ParameterDefinition(
        param_id="test_str",
        display_name="Test String",
        param_type=ParameterType.STRING,
        allowed_values=("alpha", "beta", "gamma"),
    )
    assert p.validate_value("alpha") == "alpha"
    assert p.validate_value(" beta ") == "beta"

    with pytest.raises(TypeError, match="must be a string"):
        p.validate_value(123)

    with pytest.raises(ValueError, match="not in allowed values"):
        p.validate_value("delta")

def test_int_parameter_validation():
    p = ParameterDefinition(
        param_id="test_int",
        display_name="Test Int",
        param_type=ParameterType.INT,
        min_value=10,
        max_value=100,
    )
    assert p.validate_value(50) == 50
    assert p.validate_value(10) == 10
    assert p.validate_value(100) == 100

    with pytest.raises(TypeError, match="must be an integer"):
        p.validate_value("50")

    with pytest.raises(TypeError, match="must be an integer"):
        p.validate_value(True)

    with pytest.raises(ValueError, match="must be >= 10"):
        p.validate_value(9)

    with pytest.raises(ValueError, match="must be <= 100"):
        p.validate_value(101)

def test_float_parameter_validation():
    p = ParameterDefinition(
        param_id="test_flt",
        display_name="Test Float",
        param_type=ParameterType.FLOAT,
        min_value=0.5,
        max_value=10.0,
    )
    assert p.validate_value(2.5) == 2.5
    assert p.validate_value(5) == 5.0

    with pytest.raises(TypeError, match="must be a float"):
        p.validate_value("2.5")

    with pytest.raises(ValueError, match="must be >= 0.5"):
        p.validate_value(0.4)

def test_bool_parameter_validation():
    p = ParameterDefinition(
        param_id="test_bool",
        display_name="Test Bool",
        param_type=ParameterType.BOOL,
    )
    assert p.validate_value(True) is True
    assert p.validate_value(False) is False
    assert p.validate_value("true") is True
    assert p.validate_value("false") is False

    with pytest.raises(TypeError, match="must be a boolean"):
        p.validate_value(123)

def test_uuid_parameter_validation():
    p = ParameterDefinition(
        param_id="test_uuid",
        display_name="Test UUID",
        param_type=ParameterType.UUID,
    )
    valid_uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    assert p.validate_value(valid_uuid) == valid_uuid
    assert p.validate_value(valid_uuid.upper()) == valid_uuid.lower()

    with pytest.raises(ValueError, match="must be a valid RFC 4122 UUID"):
        p.validate_value("not-a-uuid")

    with pytest.raises(TypeError, match="must be a UUID string"):
        p.validate_value(12345)

def test_hex_parameter_validation():
    p = ParameterDefinition(
        param_id="test_hex",
        display_name="Test Hex",
        param_type=ParameterType.HEX,
        max_value=16,
    )
    assert p.validate_value("0123456789abcdef") == "0123456789abcdef"
    assert p.validate_value("") == ""
    assert p.validate_value("a1") == "a1"

    with pytest.raises(ValueError, match="must have an even length"):
        p.validate_value("abc")

    with pytest.raises(ValueError, match="must contain only hexadecimal"):
        p.validate_value("xyz0")

    with pytest.raises(ValueError, match="exceeds maximum 16 characters"):
        p.validate_value("0123456789abcdef01")

def test_parameter_engine_scoping():
    p = ParameterDefinition(
        param_id="special_opt",
        display_name="Special Option",
        param_type=ParameterType.STRING,
        applicable_engines=("xray",),
    )
    assert p.validate_value("val", engine_id="xray") == "val"

    with pytest.raises(ValueError, match="not supported by engine 'sing_box'"):
        p.validate_value("val", engine_id="sing_box")

def test_variant_secret_redaction():
    p_sec = ParameterDefinition(
        param_id="token",
        display_name="Token",
        param_type=ParameterType.STRING,
        is_secret=True,
    )
    p_pub = ParameterDefinition(
        param_id="name",
        display_name="Name",
        param_type=ParameterType.STRING,
        is_secret=False,
    )

    variant = ParameterVariant(
        variant_id="test_var",
        display_name="Test Var",
        overrides={"token": "super_secret_value", "name": "public_label"},
    )

    clean_dict = variant.to_dict(
        redact_secrets=True,
        param_definitions={"token": p_sec, "name": p_pub},
    )
    assert clean_dict["overrides"]["token"] == "[REDACTED]"
    assert clean_dict["overrides"]["name"] == "public_label"
