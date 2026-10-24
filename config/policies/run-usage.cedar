// Run usage examples (section 3.5 of the run-limits design note, phase 2).
//
// For every tool the catalog marks destructive, the server keeps what the delegation run has
// done with it so far, across every hop, and hands it to Cedar before each call:
//
//   context.usage.calls             allowed calls of this server and tool in the run so far
//   context.usage.amount            the sum of the catalog's `amount` input over those calls
//                                   (0 when the catalog names none)
//   context.usage.destination_seen  the catalog's `destination` input value appeared in an
//                                   earlier allowed call of this tool in the run
//
// The catalog names the inputs per tool:
//
//   [policy.catalog.banking.send_money]
//   amount = "amount"
//   destination = "recipient"
//
//   [policy.catalog.web.get_webpage]
//   destination = "url#host"      # the host of the URL, not the whole URL (phase 2)
//
// Usage refuses nothing by itself. These policies turn it into limits that need no number in
// any token: a hard one (`forbid`) and soft ones (`@obligation("approval")`) that ask once a
// count is reached. An approval passes one call: that call is counted like any other, so the
// next one asks again. All three figures are zero or false for a tool that is not destructive.

// Soft: the second and every later payment of a run asks the user. A benign second payment
// costs one approval; an injected repeat is declined.
@id("ask_on_repeat_payment")
@obligation("approval")
forbid (principal, action == Action::"banking/send_money", resource)
when { context.usage.calls >= 1 && !context.approval.present };

// Hard: a run never sends more than 2000 in total, whatever the token says. No approval
// passes it. Overflow in Cedar arithmetic is an evaluation error, which denies the call.
@id("run_spend_cap_2000")
forbid (principal, action == Action::"banking/send_money", resource)
when {
  context.input has amount &&
  context.usage.amount + context.input.amount > 2000
};

// Soft, per destination: a second mail to the same recipient in one run asks. Mail to
// someone new does not, however many mails the run has sent.
@id("ask_on_repeat_mail_to_a_recipient")
@obligation("approval")
forbid (principal, action == Action::"workspace/send_email", resource)
when { context.usage.destination_seen && !context.approval.present };

// Soft, per site: once a run has fetched a page, fetching from a site it has not fetched
// from before asks. More pages of the same site do not. The catalog's `destination =
// "url#host"` makes `destination_seen` compare hosts, so a query string carrying data to a
// new host (the injection suite's `slack-08`) is asked whatever the path, while a second
// article on the same site is not. A value with no host is a destination of its own, so a
// new unparseable URL asks too.
@id("ask_on_a_new_site")
@obligation("approval")
forbid (principal, action == Action::"web/get_webpage", resource)
when {
  context.usage.calls >= 1 &&
  !context.usage.destination_seen &&
  !context.approval.present
};

// The permit side of this example: everything the token's capabilities allow. The
// capability stage runs before Cedar, so this cannot widen a token. Replace it with your own
// permits.
@id("permit_what_the_token_allows")
permit (principal, action, resource);
