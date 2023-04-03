// Arseny Savchenko

#include <fstream>
#include <string>
#include <variant>
#include <tuple>
#include <set>
#include <map>
#include <sstream>
#include <cstring>
#include <ranges>
#include <numeric>
#include <algorithm>
#include <functional>

namespace tcs_hw {
	template <typename T> using result = std::variant<T, std::string>;
	enum result_states { OK = 0, ERR };

	namespace fsa {
		// ------------------- Basic FSA types -------------------

		using state = std::string;
		using alpha = std::string;
		using transition = std::pair<fsa::state, std::pair<fsa::alpha, fsa::state>>;
		using transitions = std::map<state, std::map<alpha, std::set<state>>>;
		using fsa = std::tuple<std::set<state>, std::set<alpha>, state, std::set<state>, transitions>;

		namespace fsa_args {
			enum {
				STATES = 0,
				ALPHABET,
				INITIAL_STATE,
				FINAL_STATES,
				TRANSITIONS
			};
		}
	}

	namespace err {
		const char* const E2 = "E2: Some states are disjoint";
		const char* const E4 = "E4: Initial state is not defined";
		const char* const E5 = "E5: Input file is malformed";

		const char* const W1 = "W1: Accepting state is not defined";
		const char* const W2 = "W2: Some states are not reachable from the initial state";
		const char* const W3 = "W3: FSA is nondeterministic";

		namespace {
			std::set<std::string> warnings;
		}
	}

	// ---------------------------- Parsing ----------------------------

	/**
	 * Parses arguments with some condition
	 * @param in input stream
	 * @param starts_with prefix to check
	 * @param predicate condition to check on every argument
	 * @return either arguments or error
	 */

	template <typename P> [[nodiscard]] inline result<std::set<std::string>> parse_args(
			std::istream& in,
			const char* const starts_with,
			P predicate
	) noexcept {
		std::string input;

		if (!std::getline(in, input))
			return { err::E5 };

		if (!input.starts_with(starts_with) || !input.ends_with("]"))
			return { err::E5 };

		const auto start_with_len = std::strlen(starts_with);
		input.replace(0, start_with_len, "");
		input.pop_back();

		if (input.starts_with(",") || input.ends_with(","))
			return { err::E5 };

		std::set<std::string> args;
		std::stringstream input_stream(input);

		while (std::getline(input_stream, input, ',')) {
			if (!predicate(input)) return { err::E5 };
			args.insert(input);
		}

		return { std::move(args) };
	}

	/**
	 * Parses arguments
	 * @param in input stream
	 * @param starts_with prefix to check
	 * @return either arguments or error
	 */

	[[nodiscard]] inline result<std::set<std::string>> parse_args(
			std::istream& in,
			const char* const starts_with
	) noexcept {
		std::string input;

		if (!std::getline(in, input))
			return { err::E5 };

		if (!input.starts_with(starts_with) || !input.ends_with("]"))
			return { err::E5 };

		const auto start_with_len = std::strlen(starts_with);
		input.replace(0, start_with_len, "");
		input.pop_back();

		if (input.starts_with(",") || input.ends_with(","))
			return { err::E5 };

		std::set<std::string> args;
		std::stringstream input_stream(input);

		while (std::getline(input_stream, input, ','))
			args.insert(input);

		return { std::move(args) };
	}

	/**
	 * Panics with some message and stops program's execution
	 * @param OUT output stream
	 * @param MSG message formatted as stream
	 */

	#define PANIC(OUT, MSG) \
		OUT << "Error:" << std::endl << MSG << std::endl; \
		std::exit(0)

	/**
	 * Panics if state is not found
	 * @param out output stream
	 * @param state state that is not found
	 */

	inline void panic_state_not_found(std::ostream& out, const fsa::state& state) noexcept {
		PANIC(out, "E1: A state \'" << state << "\' is not in the set of states");
	}

	/**
	 * Panics if alpha is not found
	 * @param out output stream
	 * @param alpha alpha that is not found
	 */

	inline void panic_alpha_not_found(std::ostream& out, const fsa::alpha& alpha) noexcept {
		PANIC(out, "E3: A transition \'" << alpha << "\' is not represented in the alphabet");
	}

	/**
	 * Parses arguments with some predicate or panics if there is an error
	 * @param in input stream
	 * @param out output stream
	 * @param starts_with prefix to check
	 * @param predicate condition to check on every state
	 * @return parsed arguments
	 */

	template <typename P> [[nodiscard]] inline std::set<std::string> parse_args_or_panic(
			std::istream& in,
			std::ostream& out,
			const char* const starts_with,
			P predicate
	) noexcept {
		auto parse_result = parse_args(in, starts_with, predicate);

		switch (parse_result.index()) {
			case OK: return std::move(std::get<std::set<std::string>>(parse_result));
			case ERR: PANIC(out, std::get<std::string>(parse_result));
		}
	}

	/**
	 * Parses arguments or panics if there is an error
	 * @param in input stream
	 * @param out output stream
	 * @param starts_with prefix to check
	 * @return parsed arguments
	 */

	[[nodiscard]] inline std::set<std::string> parse_args_or_panic(
			std::istream& in,
			std::ostream& out,
			const char* const starts_with
	) noexcept {
		auto parse_result = parse_args(in, starts_with);

		switch (parse_result.index()) {
			case OK: return std::move(std::get<std::set<std::string>>(parse_result));
			case ERR: PANIC(out, std::get<std::string>(parse_result));
		}
	}

	/**
	 * Checks if state's name's characters are either digits or alpha
	 * @param state state to validate
	 * @return true if name is correct
	 */

	inline bool is_state_name_correct(const fsa::state& state) noexcept {
		return !state.empty() && std::all_of(state.begin(), state.end(), [](const char c) {
			return std::isalpha(c) || std::isdigit(c);
		});
	}

	/**
	 * Checks if alpha's name's characters are either digits or alpha or _
	 * @param alpha alpha to validate
	 * @return true if name is correct
	 */

	inline bool is_alpha_name_correct(const fsa::alpha& alpha) noexcept {
		return !alpha.empty() && std::all_of(alpha.begin(), alpha.end(), [](const char c) {
			return std::isalpha(c) || std::isdigit(c) || c == '_';
		});
	}

	/**
	 * Parses initial state or panics if there is an error
	 * @param in input stream
	 * @param out out stream
	 * @param states all states
	 * @return parsed state
	 */

	[[nodiscard]] inline fsa::state parse_init_state_or_panic(
			std::istream& in,
			std::ostream& out,
			const std::set<fsa::state>& states
	) noexcept {
		auto parse_init_result = parse_args(in, "init.st=[");
		std::set<fsa::state> init_states;

		switch (parse_init_result.index()) {
			case tcs_hw::OK:
				init_states = std::move(std::get<std::set<fsa::state>>(parse_init_result));
				break;

			case tcs_hw::ERR: PANIC(out, std::get<std::string>(parse_init_result));
		}

		if (init_states.empty()) { PANIC(out, err::E4); }

		if (init_states.size() > 1) { PANIC(out, err::E5); }

		auto init_state = *init_states.begin();

		if (!states.contains(init_state))
			panic_state_not_found(out, init_state);

		return init_state;
	}

	/**
	 * Parses final states or panics if there is an error
	 * @param in input stream
	 * @param out out stream
	 * @param states all states
	 * @return parsed states
	 */

	[[nodiscard]] inline std::set<fsa::state> parse_final_states_or_panic(
			std::istream& in,
			std::ostream& out,
			const std::set<fsa::state>& states
	) noexcept {
		auto final_states = tcs_hw::parse_args_or_panic(in, out, "fin.st=[");

		const auto not_present_state_it = std::find_if(
				final_states.begin(),
				final_states.end(),
				[&states](const fsa::state& state) { return states.find(state) == states.end(); }
		);

		if (not_present_state_it != final_states.end()) {
			PANIC(out, "E1: A state \'" << *not_present_state_it << "\' is not in the set of states");
		}

		if (final_states.empty()) err::warnings.insert(err::W1);
		return final_states;
	}

	/**
	 * Parses transition or panics if there is an error
	 * @param in input stream
	 * @param out out stream
	 * @param states all states
	 * @param alphabet whole alphabet
	 * @return parsed transition
	 */

	[[nodiscard]] inline fsa::transition parse_transition_or_panic(
			std::string&& in,
			std::ostream& out,
			const std::set<fsa::state>& states,
			const std::set<fsa::alpha>& alphabet
	) noexcept {
		std::stringstream input_stream(in);

		fsa::state start, finish;
		fsa::alpha alpha;

		if (!std::getline(input_stream, start, '>')) { PANIC(out, err::E5); }
		if (!std::getline(input_stream, alpha, '>')) { PANIC(out, err::E5); }
		if (!std::getline(input_stream, finish, '>')) { PANIC(out, err::E5); }
		if (!input_stream.eof()) { PANIC(out, err::E5); }

		if (!states.contains(start))
			panic_state_not_found(out, start);

		if (!alphabet.contains(alpha))
			panic_alpha_not_found(out, alpha);

		if (!states.contains(finish))
			panic_state_not_found(out, finish);

		return std::make_pair(start, std::make_pair(alpha, finish));
	}

	/**
	 * Parses transitions or panics if there is an error
	 * @param in input stream
	 * @param out out stream
	 * @param states all states
	 * @param alphabet whole alphabet
	 * @return parsed transitions
	 */

	[[nodiscard]] inline fsa::transitions parse_transitions_or_panic(
			std::istream& in,
			std::ostream& out,
			const std::set<fsa::state>& states,
			const std::set<fsa::alpha>& alphabet
	) noexcept {
		auto args = tcs_hw::parse_args_or_panic(in, out, "trans=[");
		fsa::transitions trans;

		for (auto&& [start, alpha_to_finish] : args | std::views::transform([&](std::string s) {
			return parse_transition_or_panic(std::move(s), out, states, alphabet);
		})) {
			auto&& [alpha, finish] = alpha_to_finish;
			auto& set = trans[start][alpha];
			if (!set.empty()) err::warnings.insert(err::W3);
			set.insert(finish);
		}

		return trans;
	}

	/**
	 * Parses fsa or panics if there is an error
	 * @param in input stream
	 * @param out out stream
	 * @return parsed fsa with states, alphabet and transitions
	 */

	[[nodiscard]] inline fsa::fsa parse_fsa_or_panic(
			std::istream& in,
			std::ostream& out
	) noexcept {
		// -------------------------- Parsing states --------------------------

		auto states = tcs_hw::parse_args_or_panic(in, out, "states=[", is_state_name_correct);

		// -------------------------- Parsing alphabet --------------------------

		auto alphabet = tcs_hw::parse_args_or_panic(in, out, "alpha=[", is_alpha_name_correct);

		// -------------------------- Parsing init state --------------------------

		auto init_state = tcs_hw::parse_init_state_or_panic(in, out, states);

		// -------------------------- Parsing final states --------------------------

		auto final_states = tcs_hw::parse_final_states_or_panic(in, out, states);

		// -------------------------- Parsing transitions --------------------------

		auto transitions = tcs_hw::parse_transitions_or_panic(in, out, states, alphabet);

		return std::make_tuple(states, alphabet, init_state, final_states, transitions);
	}

	// ---------------------------- Graph validation ----------------------------

	/**
	 * Deep-First-Search of FSA's undirected graph.
	 * Walks in all nodes until they were visited before.
	 * @param graph undirected graph from FSA
	 * @param cur_state current state to iterate
	 * @param walked_states previously walked states
	 * (current states should be already included at the time function executes)
	 */

	void dfs(
			const std::map<fsa::state, std::set<fsa::state>>& graph,
			const fsa::state& cur_state,
			std::set<fsa::state>& walked_states
	) noexcept {
		for (const auto& state : graph.find(cur_state)->second) {
			if (!walked_states.contains(state)) {
				walked_states.insert(state);
				dfs(graph, state, walked_states);
			}
		}
	}

	/**
	 * Deep-First-Search in FSA's transitions.
	 * Walks in all states until they were visited before.
	 * @param trans FSA's transitions
	 * @param cur_state current state to iterate
	 * @param walked_states previously walked states
	 * (current states should be already included at the time function executes)
	 */

	void dfs(
			const fsa::transitions& trans,
			const fsa::state& cur_state,
			std::set<fsa::state>& walked_states
	) noexcept {
		const auto alpha_to_states_map_it = trans.find(cur_state);

		if (alpha_to_states_map_it != trans.end()) {
			for (const auto& [alpha, states] : alpha_to_states_map_it->second) {
				for (const auto& state : states) {
					if (!walked_states.contains(state)) {
						walked_states.insert(state);
						dfs(trans, state, walked_states);
					}
				}
			}
		}
	}

	/**
	 * Checks if all states in FSA are connected (at least in undirected way).
	 * @param graph undirected graph from FSA
	 * @param states_number number of all states
	 * @return true if there are at least 2 connectivity components
	 */

	[[nodiscard]] inline bool are_states_disjoint(
			const std::map<fsa::state, std::set<fsa::state>>& graph,
			const std::size_t states_number
	) noexcept {
		if (states_number <= 1)
			return false;

		if (graph.empty())
			return true;

		const auto& start = graph.begin()->first;
		std::set<fsa::state> walked_states = { start };
		dfs(graph, start, walked_states);
		return walked_states.size() != states_number;
	}

	/**
	 * Checks if all states in FSA are connected (at least in undirected way).
	 * @param trans transitions in FSA
	 * @param states_number number of all states
	 * @param out output stream
	 * @return true if there are at least 2 connectivity components
	 */

	inline void validate_transitions(
			const fsa::transitions& trans,
			const std::size_t states_number,
			std::ostream& out
	) noexcept {
		std::map<fsa::state, std::set<fsa::state>> graph;

		for (const auto& [state_1, alpha_to_states] : trans) {
			for (const auto& [alpha, to_states] : alpha_to_states) {
				for (const auto& state_2 : to_states) {
					graph[state_1].insert(state_2);
					graph[state_2].insert(state_1);
				}
			}
		}

		if (are_states_disjoint(graph, states_number)) {
			PANIC(out, err::E2);
		}
	}

	/**
	 * Checks if some states are unreachable from initial one.
	 * @param state_machine FSA itself
	 * @return true if there is at least one state that
	 * cannot be accessed from initial one
	 */

	[[nodiscard]] inline bool are_some_states_unreachable_from_initial(const fsa::fsa& state_machine) noexcept {
		const auto& initial_state = std::get<fsa::fsa_args::INITIAL_STATE>(state_machine);
		const auto& trans = std::get<fsa::fsa_args::TRANSITIONS>(state_machine);
		const auto states_number = std::get<fsa::fsa_args::STATES>(state_machine).size();

		std::set<fsa::state> walked_states = { initial_state };
		dfs(trans, initial_state, walked_states);
		return walked_states.size() != states_number;
	}

	/**
	 * Checks if some states are unreachable from initial one.
	 * @param state_machine FSA itself
	 */

	inline void validate_all_states_reachable_from_initial(const fsa::fsa& state_machine) noexcept {
		if (are_some_states_unreachable_from_initial(state_machine)) {
			err::warnings.insert(err::W2);
		}
	}

	/**
	 * Checks if all states have all transitions from alphabet.
	 * @param state_machine FSA itself
	 * @return true if number of transitions equals
	 * to number of states multiplied by alphabet's cardinality
	 */

	inline bool is_fsa_complete(const fsa::fsa& state_machine) noexcept {
		const auto& states = std::get<fsa::fsa_args::STATES>(state_machine);
		const auto& alphabet = std::get<fsa::fsa_args::ALPHABET>(state_machine);
		const auto& transitions = std::get<fsa::fsa_args::TRANSITIONS>(state_machine);

		const auto transitions_number = std::accumulate(
				transitions.begin(),
				transitions.end(),
				0ul,
				[](const std::size_t sum, const auto& entry) {
					return sum + entry.second.size();
				}
		);

		return transitions_number == states.size() * alphabet.size();
	}

	/**
	 * 1) Checks if all states are joint. Panics otherwise
	 * 2) Checks if all states are reachable from initial one
	 * @param state_machine FSA itself
	 * @param out output stream
	 * @return all warnings during validations and fsa's completeness status
	 */

	[[nodiscard]] inline std::pair<std::set<std::string>, bool> validate_fsa(
			const fsa::fsa& state_machine,
			std::ostream& out
	) noexcept {
		validate_transitions(
				std::get<tcs_hw::fsa::fsa_args::TRANSITIONS>(state_machine),
				std::get<tcs_hw::fsa::fsa_args::STATES>(state_machine).size(),
				out
		);

		validate_all_states_reachable_from_initial(state_machine);
		return std::make_pair(err::warnings, is_fsa_complete(state_machine));
	}
}

int main() {
	std::ifstream in("fsa.txt");
	std::ofstream out("result.txt");

	const auto fsa = tcs_hw::parse_fsa_or_panic(in, out);
	in.get();

	if (!in.eof()) {
		PANIC(out, tcs_hw::err::E5);
	}

	const auto [warnings, is_fsa_complete] = tcs_hw::validate_fsa(fsa, out);

	out << (is_fsa_complete ? "FSA is complete" : "FSA is incomplete") << std::endl;

	if (!warnings.empty()) {
		out << "Warning:" << std::endl;

		for (const auto& warning : warnings)
			out << warning << std::endl;
	}

	return 0;
}
