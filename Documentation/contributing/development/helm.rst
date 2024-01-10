.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Developing upgrade-friendly Helm options
========================================

Let's say there was some feature, it has a flag. '--foo=bar' is the default in
the agent in Cilium v1.14. We could even set the Helm default in Cilium v1.14
charts to ``foo: bar``. The user doesn't explicitly configure it. Then there's
some internal change or we develop some better version of ``foo``,
``--foo=baz``. The question is, how do you update the Helm charts such that
_new users_ will adopt ``--foo=baz`` by default, but you don't break existing
users by changing their previous ``--foo=bar`` configuration to ``--foo=baz``.
If the flag wasn't specified by the user or explicitly opted in, then maybe we
keep the agent flag default to ``bar``. Then we want some way to ensure that
new users adopt ``baz``. If we set the values file to ``baz`` and we don't
provide some sort of explicit instructions for upgrade that retain ``foo: bar``
for upgrading users, then existing users will end up adopting the new default
``baz``.

In some scenarios, this flag change can mean applying invasive changes to the
datapath that we may know causes temporary disruption to during upgrade. So
rather than forcing the user to adopt the risk of upgrade _as well as_ the risk
of changing ``foo=bar`` to ``foo=baz``, we can split that down and only make
the transition when the user wants to explicitly make the transition. We could
argue that more engineering:tm: on the upgrade aspect of the feature could
eliminate this problem, but we typically haven't committed to that high of a
bar for upgrades, especially if we don't know whether the new flag or version
will be widely used. (Maybe the new flag is actually just for one user and
they'll install fresh, so we don't need to cross the upgrade bridge).

For what it's worth, this problem statement is how we ended up with the
``upgradeCompatibility`` flag. Basically it allows developers to explicitly
encode which defaults should be used for which versions of Cilium Helm install,
and change them over time. If a user wants to ensure they keep their safe
defaults from the previous version, they "just" specify
``upgradeCompatibility`` and the Helm charts will resolve the defaults as from
when they first installed Cilium. I'd be open to discussion about whether
that's a reasonable solution or there are better approaches, but that's the
gist of why we have that weird config option.>  you mean you omit them to avoid
having a default that would cause issues, right? You don't omit them to prevent
them from appearing in the docs?
