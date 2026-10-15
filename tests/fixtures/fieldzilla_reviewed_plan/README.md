# Reviewed-plan fixtures

`real_derived_plan.json` is a sanitized real-plan fixture: the seven reviewed resource changes and the
three deferred IAM policy-document reads taken from the failed FieldZilla staging plan (run 38708701699,
artifact 11959187967) with the AWS account id, KMS key id, Secrets Manager ids and image digests replaced
by synthetic values. Everything else (variables aside) was dropped. It keeps the real representation of
unknown values (`after_unknown`, deferred policy documents, null list elements).

`real_derived_spec.json` is the consumer-owned expected-change file for that subset. Its plan id
(`synthetic-reviewed-plan`) and layout are illustrative; the tests copy it to
`.github/opentofu-plans/<plan-id>.json` in a temporary workspace.

All other plans in `tests/test_fieldzilla_reviewed_plan.py` are synthetic variants of this fixture.
