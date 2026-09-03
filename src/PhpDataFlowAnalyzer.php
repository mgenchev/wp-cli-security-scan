<?php
/**
 * Lightweight PHP token/data-flow analyzer used by WP-CLI Security Scan.
 *
 * This analyzer never executes scanned code. It follows a deliberately small
 * PHP subset that is common in malware: assignments, string construction,
 * decoders, request sources, dynamic callbacks, command/code execution,
 * includes and file writes.
 */

class Security_Scan_Php_Data_Flow_Analyzer {
	private const MAX_RECURSION_DEPTH = 4;
	private const MAX_STATIC_DECODE_BYTES = 2097152;

	private const SUPERGLOBALS = [
		'$_GET',
		'$_POST',
		'$_REQUEST',
		'$_COOKIE',
		'$_FILES',
		'$_SERVER',
	];

	private const DECODERS = [
		'base64_decode',
		'gzinflate',
		'gzuncompress',
		'gzdecode',
		'str_rot13',
		'strrev',
		'rawurldecode',
		'urldecode',
		'hex2bin',
		'convert_uudecode',
		'openssl_decrypt',
	];

	private const COMMAND_SINKS = [
		'system',
		'exec',
		'shell_exec',
		'passthru',
		'popen',
		'proc_open',
		'pcntl_exec',
	];

	private const CODE_SINKS = [
		'assert',
		'create_function',
	];

	private const FILE_WRITE_SINKS = [
		'file_put_contents',
		'fwrite',
		'fputs',
		'copy',
		'rename',
		'move_uploaded_file',
	];

	private const REMOTE_SOURCES = [
		'file_get_contents',
		'fopen',
		'curl_exec',
		'wp_remote_get',
		'wp_remote_post',
		'wp_remote_request',
		'wp_safe_remote_get',
		'wp_safe_remote_post',
		'wp_safe_remote_request',
		'wp_remote_retrieve_body',
	];

	private const REQUEST_SOURCE_FUNCTIONS = [
		'filter_input',
		'getallheaders',
		'apache_request_headers',
	];


	/**
	 * WordPress URL builders whose result is provably local to the current site/network.
	 *
	 * Sensitive data sent back to one of these URLs is not external exfiltration.
	 * The hint is only trusted while the target remains non-tainted and contains no
	 * independently observed remote URL evidence.
	 */
	private const LOCAL_URL_FUNCTIONS = [
		'admin_url',
		'home_url',
		'site_url',
		'network_admin_url',
		'network_home_url',
		'network_site_url',
		'rest_url',
		'self_admin_url',
		'user_admin_url',
		'content_url',
		'includes_url',
		'plugins_url',
		'wp_login_url',
		'wp_logout_url',
	];

	/**
	 * Functions whose result is a boolean type/property check rather than the
	 * underlying payload. Their arguments may be tainted/remote, but the return
	 * value itself cannot carry executable content.
	 */
	private const BOOLEAN_PREDICATE_FUNCTIONS = [
		'is_array',
		'is_bool',
		'is_callable',
		'is_double',
		'is_float',
		'is_int',
		'is_integer',
		'is_iterable',
		'is_long',
		'is_null',
		'is_numeric',
		'is_object',
		'is_real',
		'is_resource',
		'is_scalar',
		'is_string',
	];

	/**
	 * Collection helpers whose return value derives from data arguments rather
	 * than from the callback/control argument itself. Modeling these explicitly
	 * prevents callback/closure taint from contaminating the returned collection.
	 */
	private const FIRST_ARGUMENT_VALUE_FUNCTIONS = [
		'array_filter',
		'array_values',
		'array_unique',
		'array_reverse',
		'array_slice',
		'array_chunk',
		'array_column',
		'array_shift',
		'array_pop',
		'current',
		'reset',
		'end',
	];


	private const OUTBOUND_HTTP_SINKS = [
		'wp_remote_get',
		'wp_remote_post',
		'wp_remote_request',
		'wp_safe_remote_get',
		'wp_safe_remote_post',
		'wp_safe_remote_request',
	];

	private const OUTBOUND_MAIL_SINKS = [
		'mail',
		'wp_mail',
	];

	private const SOCKET_OPEN_FUNCTIONS = [
		'fsockopen',
		'pfsockopen',
		'socket_create',
		'socket_create_listen',
		'socket_import_stream',
		'socket_accept',
		'socket_addrinfo_bind',
		'socket_addrinfo_connect',
		'socket_wsaprotocol_info_import',
		'stream_socket_client',
	];

	private const SOCKET_WRITE_FUNCTIONS = [
		'socket_write',
		'socket_send',
		'socket_sendto',
		'socket_sendmsg',
		'stream_socket_sendto',
	];

	private const CALLBACK_SINKS = [
		'array_map'                  => 0,
		'array_filter'               => 1,
		'array_walk'                 => 1,
		'array_walk_recursive'       => 1,
		'array_reduce'               => 1,
		'usort'                      => 1,
		'uasort'                     => 1,
		'uksort'                     => 1,
		'array_diff_ukey'            => -1,
		'array_intersect_ukey'       => -1,
		'array_udiff'                => -1,
		'array_uintersect'           => -1,
		'preg_replace_callback'      => 1,
		'register_shutdown_function' => 0,
		'register_tick_function'     => 0,
		'set_error_handler'          => 0,
		'set_exception_handler'      => 0,
		'spl_autoload_register'      => 0,
	];

	private $known_iocs = [];
	private $findings = [];
	private $seen = [];
	private $base_line = 1;
	private $analysis_depth = 0;
	private $scopes = [];
	private $function_summaries = [];
	private $local_decoder_functions = [];

	public function __construct( array $known_iocs = [] ) {
		foreach ( $known_iocs as $ioc ) {
			$ioc = trim( (string) $ioc );
			if ( '' !== $ioc ) {
				$this->known_iocs[] = $ioc;
			}
		}
	}

	/**
	 * Analyze PHP text and return semantic findings.
	 */
	public function analyze( $code, $base_line = 1, $analysis_depth = 0 ) {
		$this->findings = [];
		$this->seen = [];
		$this->base_line = max( 1, (int) $base_line );
		$this->analysis_depth = max( 0, (int) $analysis_depth );
		$this->scopes = [ $this->new_scope() ];
		$this->function_summaries = [];
		$this->local_decoder_functions = [];

		$source = (string) $code;
		if ( false === strpos( $source, '<?' ) ) {
			$source = '<?php ' . $source;
		}

		$tokens = $this->normalize_tokens( token_get_all( $source ) );
		$this->function_summaries = $this->collect_function_summaries( $tokens );
		$this->analyze_tokens( $tokens );
		$this->analyze_global_patterns( $source );

		return $this->findings;
	}

	private function new_scope() {
		return [
			'vars'                  => [],
			'symbol_table_tainted'  => false,
		];
	}

	private function normalize_tokens( array $tokens ) {
		$normalized = [];
		$current_line = 1;

		foreach ( $tokens as $token ) {
			if ( is_array( $token ) ) {
				$normalized[] = [
					'id'   => $token[0],
					'text' => $token[1],
					'line' => $token[2],
				];
				$current_line = $token[2] + substr_count( $token[1], "\n" );
				continue;
			}

			$normalized[] = [
				'id'   => null,
				'text' => $token,
				'line' => $current_line,
			];
			$current_line += substr_count( $token, "\n" );
		}

		return $normalized;
	}

	private function analyze_tokens( array $tokens ) {
		$count = count( $tokens );
		$brace_depth = 0;
		$function_depths = [];
		$pending_function = false;

		for ( $i = 0; $i < $count; $i++ ) {
			$token = $tokens[ $i ];

			if ( T_FUNCTION === $token['id'] ) {
				$pending_function = true;
				continue;
			}

			if ( $pending_function && ';' === $token['text'] ) {
				$pending_function = false;
			}

			if ( '{' === $token['text'] ) {
				$brace_depth++;
				if ( $pending_function ) {
					$this->scopes[] = $this->new_scope();
					$function_depths[] = $brace_depth;
					$pending_function = false;
				}
				continue;
			}

			if ( '}' === $token['text'] ) {
				if ( ! empty( $function_depths ) && end( $function_depths ) === $brace_depth ) {
					array_pop( $function_depths );
					if ( count( $this->scopes ) > 1 ) {
						array_pop( $this->scopes );
					}
				}
				$brace_depth = max( 0, $brace_depth - 1 );
				continue;
			}

			if ( T_VARIABLE === $token['id'] ) {
				$assignment = $this->parse_assignment_at( $tokens, $i );
				if ( null !== $assignment ) {
					$state = $this->evaluate_expression( $assignment['rhs'] );
					$this->set_variable_state( $assignment['lhs'], $state );
					$i = $assignment['end'];
					continue;
				}
			}

			if ( T_EVAL === $token['id'] ) {
				$call = $this->parse_parenthesized_call_after( $tokens, $i );
				if ( null !== $call ) {
					$arg = isset( $call['args'][0] ) ? $this->evaluate_expression( $call['args'][0] ) : $this->empty_state();
					$this->report_eval_sink( $arg, $token['line'] );
				}
				continue;
			}

			if ( in_array( $token['id'], [ T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE ], true ) ) {
				$end = $this->find_statement_end( $tokens, $i + 1 );
				$expr = array_slice( $tokens, $i + 1, max( 0, $end - $i - 1 ) );
				$state = $this->evaluate_expression( $expr );
				$this->report_include_sink( $state, $token['line'] );
				continue;
			}

			if ( '`' === $token['text'] ) {
				$end = $this->find_text_token( $tokens, '`', $i + 1 );
				if ( null !== $end ) {
					$state = $this->evaluate_expression( array_slice( $tokens, $i + 1, $end - $i - 1 ) );
					if ( $state['tainted'] ) {
						$this->add_finding( 'critical', 99, 'dataflow_tainted_backticks', 'Request-controlled data reaches shell backtick execution', $token['line'] );
					}
					$i = $end;
				}
				continue;
			}

			if ( T_VARIABLE === $token['id'] ) {
				$method_call = $this->parse_object_method_call_at( $tokens, $i );
				if ( null !== $method_call ) {
					$this->evaluate_object_method_call( $method_call );
					$i = max( $i, $method_call['end'] );
					continue;
				}
			}

			$call = $this->parse_callable_at( $tokens, $i );
			if ( null !== $call ) {
				$this->evaluate_call( $call['callback'], $call['args'], $call['line'] );
				$i = max( $i, $call['end'] );
			}
		}
	}

	private function parse_assignment_at( array $tokens, $index ) {
		$lhs = $this->parse_variable_reference( $tokens, $index );
		if ( null === $lhs ) {
			return null;
		}

		$equals = $this->next_significant_index( $tokens, $lhs['end'] + 1 );
		if ( null === $equals || '=' !== $tokens[ $equals ]['text'] ) {
			return null;
		}

		// Do not treat comparison/compound assignments as simple state replacement.
		$previous = $this->previous_significant_index( $tokens, $equals - 1 );
		$next = $this->next_significant_index( $tokens, $equals + 1 );
		if ( ( null !== $previous && in_array( $tokens[ $previous ]['text'], [ '!', '<', '>', '=' ], true ) ) || ( null !== $next && '=' === $tokens[ $next ]['text'] ) ) {
			return null;
		}

		$end = $this->find_statement_end( $tokens, $equals + 1 );
		if ( $end <= $equals ) {
			return null;
		}

		return [
			'lhs' => $lhs['key'],
			'rhs' => array_slice( $tokens, $equals + 1, $end - $equals - 1 ),
			'end' => $end,
		];
	}

	private function parse_variable_reference( array $tokens, $index ) {
		if ( ! isset( $tokens[ $index ] ) || T_VARIABLE !== $tokens[ $index ]['id'] ) {
			return null;
		}

		$key = $tokens[ $index ]['text'];
		$end = $index;
		$cursor = $this->next_significant_index( $tokens, $index + 1 );

		while ( null !== $cursor && '[' === $tokens[ $cursor ]['text'] ) {
			$close = $this->find_matching( $tokens, $cursor, '[', ']' );
			if ( null === $close ) {
				break;
			}

			$key_tokens = $this->trim_tokens( array_slice( $tokens, $cursor + 1, $close - $cursor - 1 ) );
			$key_state = $this->evaluate_expression( $key_tokens );
			$key_part = null !== $key_state['literal'] ? (string) $key_state['literal'] : '*';
			$key .= '[' . $key_part . ']';
			$end = $close;
			$cursor = $this->next_significant_index( $tokens, $close + 1 );
		}

		return [
			'key'  => $key,
			'end'  => $end,
			'line' => $tokens[ $index ]['line'],
		];
	}

	private function evaluate_expression( array $tokens, $depth = 0 ) {
		if ( $depth > 20 ) {
			return $this->empty_state();
		}

		$tokens = $this->trim_tokens( $tokens );
		if ( empty( $tokens ) ) {
			return $this->empty_state();
		}

		while ( $this->is_wrapped_in_parentheses( $tokens ) ) {
			$tokens = $this->trim_tokens( array_slice( $tokens, 1, -1 ) );
		}

		$concat_parts = $this->split_top_level( $tokens, '.' );
		if ( count( $concat_parts ) > 1 ) {
			$states = [];
			foreach ( $concat_parts as $part ) {
				$states[] = $this->evaluate_expression( $part, $depth + 1 );
			}
			return $this->merge_concatenation_states( $states );
		}

		$first = $tokens[0];

		// Anonymous and arrow functions have a statically defined callback identity.
		// Captured request-derived values belong to the closure payload/body state,
		// not to the identity of the callback itself. Treating captures as callback
		// taint causes false positives for normal filtering/configuration closures.
		$is_arrow_function = defined( 'T_FN' ) && constant( 'T_FN' ) === $first['id'];
		if ( T_FUNCTION === $first['id'] || $is_arrow_function ) {
			$state = $this->empty_state();
			$state['transport'] = 'closure';
			return $state;
		}

		if ( T_EVAL === $first['id'] ) {
			$call = $this->parse_parenthesized_call_after( $tokens, 0 );
			if ( null !== $call ) {
				$state = isset( $call['args'][0] ) ? $this->evaluate_expression( $call['args'][0], $depth + 1 ) : $this->empty_state();
				$this->report_eval_sink( $state, $first['line'] );
			}
			return $this->empty_state();
		}


		if ( T_CONSTANT_ENCAPSED_STRING === $first['id'] && 1 === count( $tokens ) ) {
			return $this->literal_state( $this->decode_php_string_literal( $first['text'] ) );
		}

		if ( in_array( $first['id'], [ T_LNUMBER, T_DNUMBER ], true ) && 1 === count( $tokens ) ) {
			return $this->literal_state( $first['text'] );
		}

		if ( T_NEW === $first['id'] ) {
			$reflection = $this->evaluate_reflection_constructor( $tokens, $depth );
			if ( null !== $reflection ) {
				return $reflection;
			}
		}

		if ( T_VARIABLE === $first['id'] ) {
			$ref = $this->parse_variable_reference( $tokens, 0 );
			if ( null !== $ref ) {
				$next = $this->next_significant_index( $tokens, $ref['end'] + 1 );
				if ( null !== $next && '(' === $tokens[ $next ]['text'] ) {
					$call = $this->parse_callable_at( $tokens, 0 );
					if ( null !== $call ) {
						return $this->evaluate_call( $call['callback'], $call['args'], $call['line'] );
					}
				}

				return $this->get_variable_state( $ref['key'] );
			}
		}

		$call = $this->parse_callable_at( $tokens, 0 );
		if ( null !== $call && $call['end'] >= count( $tokens ) - 1 ) {
			return $this->evaluate_call( $call['callback'], $call['args'], $call['line'] );
		}

		// Conservative fallback: merge any variables and calls visible in the expression.
		$state = $this->empty_state();
		for ( $i = 0; $i < count( $tokens ); $i++ ) {
			if ( T_VARIABLE === $tokens[ $i ]['id'] ) {
				$ref = $this->parse_variable_reference( $tokens, $i );
				if ( null !== $ref ) {
					$state = $this->merge_states( $state, $this->get_variable_state( $ref['key'] ) );
					$i = $ref['end'];
				}
			} elseif ( T_CONSTANT_ENCAPSED_STRING === $tokens[ $i ]['id'] ) {
				$state = $this->merge_states( $state, $this->literal_state( $this->decode_php_string_literal( $tokens[ $i ]['text'] ) ) );
			}
		}

		return $state;
	}

	/**
	 * Model ReflectionFunction targets without executing reflected code.
	 */
	private function evaluate_reflection_constructor( array $tokens, $depth ) {
		$class_index = $this->next_significant_index( $tokens, 1 );
		if ( null === $class_index ) {
			return null;
		}

		$class_name = strtolower( trim( $tokens[ $class_index ]['text'], "\\" ) );
		if ( 'reflectionfunction' !== $class_name ) {
			return null;
		}

		$call = $this->parse_parenthesized_call_after( $tokens, $class_index );
		if ( null === $call ) {
			return null;
		}

		$target = isset( $call['args'][0] )
			? $this->evaluate_expression( $call['args'][0], $depth + 1 )
			: $this->empty_state();
		$target['transport'] = 'reflection_function';
		return $target;
	}

	/**
	 * Parse $object->method(...) for reflection invocation handling.
	 */
	private function parse_object_method_call_at( array $tokens, $index ) {
		$object = $this->parse_variable_reference( $tokens, $index );
		if ( null === $object ) {
			return null;
		}

		$operator = $this->next_significant_index( $tokens, $object['end'] + 1 );
		if ( null === $operator || ( T_OBJECT_OPERATOR !== $tokens[ $operator ]['id'] && '->' !== $tokens[ $operator ]['text'] ) ) {
			return null;
		}

		$method_index = $this->next_significant_index( $tokens, $operator + 1 );
		if ( null === $method_index || T_STRING !== $tokens[ $method_index ]['id'] ) {
			return null;
		}

		$method = strtolower( $tokens[ $method_index ]['text'] );
		if ( ! in_array( $method, [ 'invoke', 'invokeargs' ], true ) ) {
			return null;
		}

		$call = $this->parse_parenthesized_call_after( $tokens, $method_index );
		if ( null === $call ) {
			return null;
		}

		return [
			'object' => $object['key'],
			'method' => $method,
			'args'   => $call['args'],
			'line'   => $tokens[ $method_index ]['line'],
			'end'    => $call['end'],
		];
	}

	/**
	 * Detect ReflectionFunction invocation of dangerous/dynamic targets.
	 */
	private function evaluate_object_method_call( array $call ) {
		$object = $this->get_variable_state( $call['object'] );
		if ( 'reflection_function' !== $object['transport'] ) {
			return;
		}

		$args = [];
		foreach ( $call['args'] as $arg_tokens ) {
			$args[] = $this->evaluate_expression( $arg_tokens, 1 );
		}
		$payload = $this->merge_argument_states( $args );
		$target = null !== $object['literal'] ? strtolower( trim( $object['literal'], "\\" ) ) : null;
		$line = $this->absolute_line( $call['line'] );

		if ( null !== $target && in_array( $target, self::COMMAND_SINKS, true ) ) {
			if ( $payload['tainted'] || $payload['decoded'] || $payload['remote'] ) {
				$this->add_finding( 'critical', 99, 'dataflow_reflection_command', 'Untrusted data reaches OS command execution through ReflectionFunction', $line, true, $payload['sources'] );
			} elseif ( $object['decoded'] ) {
				$this->add_finding( 'high', 95, 'dataflow_reflection_command_target', 'Obfuscated ReflectionFunction target resolves to an OS command primitive', $line, true );
			}
			return;
		}

		if ( null !== $target && in_array( $target, self::CODE_SINKS, true ) ) {
			if ( $payload['tainted'] || $payload['decoded'] || $payload['remote'] ) {
				$this->add_finding( 'critical', 99, 'dataflow_reflection_code', 'Untrusted data reaches dynamic PHP execution through ReflectionFunction', $line, true, $payload['sources'] );
			}
			return;
		}

		if ( ( $object['tainted'] || $object['decoded'] ) && ( $payload['tainted'] || $payload['decoded'] || $payload['remote'] ) ) {
			$this->add_finding( 'critical', 98, 'dataflow_reflection_dynamic', 'Obfuscated or request-controlled ReflectionFunction target is invoked with untrusted data', $line, true, $payload['sources'] );
		}
	}

	private function parse_callable_at( array $tokens, $index ) {
		if ( ! isset( $tokens[ $index ] ) ) {
			return null;
		}

		$callback = null;
		$end_callback = $index;
		$line = $tokens[ $index ]['line'];

		if ( T_STRING === $tokens[ $index ]['id'] ) {
			$previous = $this->previous_significant_index( $tokens, $index - 1 );
			if ( null !== $previous ) {
				$previous_id = $tokens[ $previous ]['id'];
				$previous_text = $tokens[ $previous ]['text'];
				if ( in_array( $previous_id, [ T_FUNCTION, T_NEW, T_OBJECT_OPERATOR, T_DOUBLE_COLON ], true ) || in_array( $previous_text, [ '->', '::' ], true ) ) {
					return null;
				}
			}
			$callback = $this->literal_state( strtolower( $tokens[ $index ]['text'] ) );
		} elseif ( T_VARIABLE === $tokens[ $index ]['id'] ) {
			$ref = $this->parse_variable_reference( $tokens, $index );
			if ( null === $ref ) {
				return null;
			}
			$callback = $this->get_variable_state( $ref['key'] );
			$end_callback = $ref['end'];
		} else {
			return null;
		}

		$open = $this->next_significant_index( $tokens, $end_callback + 1 );
		if ( null === $open || '(' !== $tokens[ $open ]['text'] ) {
			return null;
		}

		$close = $this->find_matching( $tokens, $open, '(', ')' );
		if ( null === $close ) {
			return null;
		}

		return [
			'callback' => $callback,
			'args'     => $this->split_arguments( array_slice( $tokens, $open + 1, $close - $open - 1 ) ),
			'line'     => $line,
			'end'      => $close,
		];
	}

	private function parse_parenthesized_call_after( array $tokens, $index ) {
		$open = $this->next_significant_index( $tokens, $index + 1 );
		if ( null === $open || '(' !== $tokens[ $open ]['text'] ) {
			return null;
		}
		$close = $this->find_matching( $tokens, $open, '(', ')' );
		if ( null === $close ) {
			return null;
		}

		return [
			'args' => $this->split_arguments( array_slice( $tokens, $open + 1, $close - $open - 1 ) ),
			'end'  => $close,
		];
	}

	private function evaluate_call( array $callback, array $argument_tokens, $line ) {
		$args = [];
		foreach ( $argument_tokens as $arg_tokens ) {
			$args[] = $this->evaluate_expression( $arg_tokens, 1 );
		}

		$name = null !== $callback['literal'] ? strtolower( trim( $callback['literal'], "\\" ) ) : null;
		$line = $this->absolute_line( $line );

		if ( null === $name ) {
			if ( $callback['tainted'] ) {
				$has_tainted_arg = $this->any_state( $args, 'tainted' );
				$confidence = $has_tainted_arg ? 99 : 94;
				$this->add_finding( 'critical', $confidence, 'dataflow_tainted_dynamic_callback', 'Request-controlled value is used as a dynamic function/callback', $line, true, $callback['sources'] );
			} elseif ( $callback['decoded'] && ( $this->any_state( $args, 'tainted' ) || $this->any_state( $args, 'decoded' ) || $this->any_state( $args, 'remote' ) ) ) {
				$payload = $this->merge_argument_states( $args );
				$this->add_finding( 'critical', 98, 'dataflow_decoded_dynamic_callback', 'Obfuscated/decoded value is used as a dynamic function with untrusted arguments', $line, true, $payload['sources'] );
			}
			return $this->merge_argument_states( $args );
		}

		if ( 'curl_init' === $name ) {
			$state = isset( $args[0] ) ? $args[0] : $this->empty_state();
			$state['transport'] = 'curl';
			return $state;
		}

		if ( 'curl_setopt' === $name ) {
			$this->apply_curl_setopt( $argument_tokens, $args );
			return $this->empty_state();
		}

		if ( 'curl_setopt_array' === $name ) {
			$this->apply_curl_setopt_array( $argument_tokens, $args );
			return $this->empty_state();
		}

		if ( 'curl_exec' === $name ) {
			$handle = isset( $args[0] ) ? $args[0] : $this->empty_state();
			$this->report_outbound_sink( 'HTTP', $handle, $this->empty_state(), $line, 'dataflow_sensitive_curl_exfil' );
			$response = $this->empty_state();
			$response['remote'] = true;
			return $response;
		}

		if ( in_array( $name, self::SOCKET_OPEN_FUNCTIONS, true ) ) {
			$state = $this->merge_argument_states( $args );
			$state['transport'] = 'socket';
			return $state;
		}

		if ( 'socket_connect' === $name && isset( $args[0] ) ) {
			$this->merge_state_into_argument_variable( $argument_tokens, 0, $this->merge_argument_states( array_slice( $args, 1 ) ), 'socket' );
			return $this->empty_state();
		}

		if ( in_array( $name, self::SOCKET_WRITE_FUNCTIONS, true ) ) {
			$handle = isset( $args[0] ) ? $args[0] : $this->empty_state();
			$content = isset( $args[1] ) ? $args[1] : $this->empty_state();
			if ( 'socket_sendmsg' === $name ) {
				$content = isset( $args[1] ) ? $args[1] : $content;
			}
			$this->report_outbound_sink( 'socket', $content, $handle, $line, 'dataflow_sensitive_socket_exfil' );
			return $this->empty_state();
		}

		if ( in_array( $name, self::OUTBOUND_HTTP_SINKS, true ) ) {
			$target = isset( $args[0] ) ? $args[0] : $this->empty_state();
			$payload = $target;
			if ( false === strpos( $name, '_get' ) && isset( $args[1] ) ) {
				$payload = $this->merge_states( $payload, $args[1] );
			}
			$this->report_outbound_sink( 'HTTP', $payload, $target, $line, 'dataflow_sensitive_http_exfil' );
		}

		if ( in_array( $name, self::OUTBOUND_MAIL_SINKS, true ) ) {
			$payload = $this->merge_argument_states( array_slice( $args, 1 ) );
			$this->report_outbound_sink( 'email', $payload, isset( $args[0] ) ? $args[0] : $this->empty_state(), $line, 'dataflow_sensitive_mail_exfil' );
		}

		if ( in_array( $name, self::COMMAND_SINKS, true ) ) {
			$input = isset( $args[0] ) ? $args[0] : $this->empty_state();
			if ( $input['tainted'] ) {
				if ( $callback['decoded'] ) {
					$this->add_finding( 'critical', 99, 'dataflow_obfuscated_command_taint', 'Obfuscated OS command function receives request-controlled data', $line, true, $input['sources'] );
				} else {
					$this->add_finding( 'critical', 99, 'dataflow_command_taint', 'Request-controlled data reaches OS command execution', $line, true, $input['sources'] );
				}
			} elseif ( $input['decoded'] || $input['remote'] ) {
				$this->add_finding( 'critical', 97, 'dataflow_command_payload', 'Decoded or remotely sourced data reaches OS command execution', $line, true, $input['sources'] );
			} elseif ( $callback['decoded'] ) {
				$this->add_finding( 'high', 94, 'dataflow_decoded_command_name', 'Obfuscated function name resolves to an OS command execution primitive', $line, true );
			}
			return $this->empty_state();
		}

		if ( in_array( $name, self::CODE_SINKS, true ) ) {
			$body_index = 'create_function' === $name ? 1 : 0;
			$input = isset( $args[ $body_index ] ) ? $args[ $body_index ] : $this->empty_state();
			if ( $input['tainted'] ) {
				if ( $callback['decoded'] ) {
					$this->add_finding( 'critical', 99, 'dataflow_obfuscated_code_taint', 'Obfuscated code-execution function receives request-controlled data', $line, true, $input['sources'] );
				} else {
					$this->add_finding( 'critical', 99, 'dataflow_code_taint', 'Request-controlled data reaches dynamic PHP code execution', $line, true, $input['sources'] );
				}
			} elseif ( $input['decoded'] || $input['remote'] ) {
				$this->add_finding( 'critical', 98, 'dataflow_code_payload', 'Decoded or remotely sourced payload reaches dynamic PHP code execution', $line, true, $input['sources'] );
			} elseif ( $callback['decoded'] ) {
				$this->add_finding( 'high', 94, 'dataflow_decoded_code_sink_name', 'Obfuscated function name resolves to a dynamic code execution primitive', $line, true );
			}
			return $this->empty_state();
		}

		if ( 'call_user_func' === $name || 'call_user_func_array' === $name ) {
			$dynamic = isset( $args[0] ) ? $args[0] : $this->empty_state();
			$payload_args = array_slice( $args, 1 );
			$this->report_dynamic_callback_sink( $dynamic, $payload_args, $line );
			return $this->empty_state();
		}

		if ( isset( self::CALLBACK_SINKS[ $name ] ) ) {
			$callback_index = self::CALLBACK_SINKS[ $name ];
			if ( $callback_index < 0 ) {
				$callback_index = count( $args ) - 1;
			}
			if ( isset( $args[ $callback_index ] ) ) {
				$payload_args = $args;
				unset( $payload_args[ $callback_index ] );
				$this->report_dynamic_callback_sink( $args[ $callback_index ], array_values( $payload_args ), $line );
			}
		}

		if ( 'extract' === $name && isset( $args[0] ) && $args[0]['tainted'] ) {
			$this->mark_symbol_table_tainted();
		}

		if ( 'parse_str' === $name && isset( $args[0] ) && $args[0]['tainted'] && count( $args ) < 2 ) {
			$this->mark_symbol_table_tainted();
		}

		if ( in_array( $name, self::FILE_WRITE_SINKS, true ) ) {
			$this->report_file_write_sink( $name, $args, $line );
		}

		if ( in_array( $name, self::DECODERS, true ) ) {
			return $this->evaluate_decoder( $name, $args, $line );
		}

		if ( 'chr' === $name && isset( $args[0] ) && null !== $args[0]['literal'] && is_numeric( $args[0]['literal'] ) ) {
			$value = (int) $args[0]['literal'];
			if ( $value >= 0 && $value <= 255 ) {
				return $this->literal_state( chr( $value ) );
			}
		}


		if ( in_array( $name, self::LOCAL_URL_FUNCTIONS, true ) ) {
			$state = $this->merge_argument_states( $args );
			$state['local_url_hint'] = true;
			$state['remote_url_hint'] = false;
			$state['remote'] = false;
			return $state;
		}

		// Collection callbacks control filtering/transformation but are not data
		// returned by helpers such as array_filter(). Do not merge callback taint
		// into the collection result.
		if ( in_array( $name, self::FIRST_ARGUMENT_VALUE_FUNCTIONS, true ) ) {
			return isset( $args[0] ) ? $args[0] : $this->empty_state();
		}

		if ( 'array_map' === $name ) {
			return $this->merge_argument_states( array_slice( $args, 1 ) );
		}

		if ( in_array( $name, self::BOOLEAN_PREDICATE_FUNCTIONS, true ) ) {
			return $this->empty_state();
		}

		if ( in_array( $name, self::REQUEST_SOURCE_FUNCTIONS, true ) ) {
			if ( 'filter_input' === $name ) {
				$field = isset( $args[1] ) && null !== $args[1]['literal'] ? (string) $args[1]['literal'] : '*';
				return $this->tainted_state( 'filter_input[' . $field . ']' );
			}
			return $this->tainted_state( 'request-headers' );
		}

		if ( in_array( $name, self::REMOTE_SOURCES, true ) ) {
			$state = $this->merge_argument_states( $args );
			if ( 'file_get_contents' === $name || 'fopen' === $name ) {
				$first = isset( $args[0] ) ? $args[0] : $this->empty_state();
				if ( null !== $first['literal'] && 0 === stripos( $first['literal'], 'php://input' ) ) {
					$state['tainted'] = true;
					$state['sources']['php://input'] = true;
					$state['remote'] = false;
					return $state;
				}

				// Local streams/files are not remote content. A literal/constructed URL
				// is marked remote, while a request-controlled dynamic target remains
				// tainted through the merged argument state.
				if ( $first['remote_url_hint'] ) {
					$this->report_outbound_sink( 'HTTP', $first, $first, $line, 'dataflow_sensitive_url_exfil' );
					$state['remote'] = true;
				}
				return $state;
			}

			$state['remote'] = true;
			return $state;
		}

		$this->apply_local_function_summary( $name, $args, $line );

		$state = $this->merge_argument_states( $args );
		if ( isset( $this->local_decoder_functions[ $name ] ) ) {
			$state['decoded'] = true;
			$state['literal'] = null;
			$state['transforms'][ 'local:' . $name ] = true;
		}

		return $state;
	}

	private function report_eval_sink( array $state, $token_line ) {
		$line = $this->absolute_line( $token_line );
		if ( $state['tainted'] ) {
			$this->add_finding( 'critical', 99, 'dataflow_eval_taint', 'Request-controlled data reaches eval()', $line, true, $state['sources'] );
		} elseif ( $state['decoded'] || $state['remote'] ) {
			$this->add_finding( 'critical', 99, 'dataflow_eval_payload', 'Decoded or remotely sourced payload reaches eval()', $line, true, $state['sources'] );
		}
	}

	private function report_include_sink( array $state, $token_line ) {
		$line = $this->absolute_line( $token_line );
		if ( $state['tainted'] ) {
			$this->add_finding( 'critical', 99, 'dataflow_include_taint', 'Request-controlled data reaches include/require', $line, true, $state['sources'] );
		} elseif ( $state['remote'] ) {
			$this->add_finding( 'critical', 98, 'dataflow_include_remote', 'Remotely sourced path/content reaches include/require', $line, true, $state['sources'] );
		} elseif ( null !== $state['literal'] && preg_match( '~^(?:https?://|php://|data:)~i', $state['literal'] ) ) {
			$this->add_finding( 'high', 94, 'dataflow_include_wrapper', 'include/require uses a remote or executable stream wrapper', $line, true );
		}
	}

	private function report_dynamic_callback_sink( array $callback, array $payload_args, $line ) {
		$name = null !== $callback['literal'] ? strtolower( trim( $callback['literal'], "\\" ) ) : null;
		$payload_tainted = $this->any_state( $payload_args, 'tainted' );
		$payload_decoded = $this->any_state( $payload_args, 'decoded' ) || $this->any_state( $payload_args, 'remote' );

		if ( $callback['tainted'] ) {
			$this->add_finding( 'critical', $payload_tainted ? 99 : 96, 'dataflow_tainted_callback_sink', 'Request-controlled callback is passed to a PHP callback executor', $line, true );
			return;
		}

		if ( null !== $name && ( in_array( $name, self::COMMAND_SINKS, true ) || in_array( $name, self::CODE_SINKS, true ) || in_array( $name, self::FILE_WRITE_SINKS, true ) ) ) {
			if ( $payload_tainted || $payload_decoded || $callback['decoded'] ) {
				$this->add_finding( 'critical', 98, 'dataflow_dangerous_callback_sink', 'Dangerous function is invoked indirectly through a callback API', $line, true );
			}
		}
	}

	private function report_file_write_sink( $name, array $args, $line ) {
		$path = $this->empty_state();
		$content = $this->empty_state();

		if ( in_array( $name, [ 'fwrite', 'fputs' ], true ) && isset( $args[0] ) && 'socket' === $args[0]['transport'] ) {
			$content = isset( $args[1] ) ? $args[1] : $this->empty_state();
			$this->report_outbound_sink( 'socket', $content, $args[0], $line, 'dataflow_sensitive_socket_exfil' );
		}

		switch ( $name ) {
			case 'file_put_contents':
				$path = isset( $args[0] ) ? $args[0] : $this->empty_state();
				$content = isset( $args[1] ) ? $args[1] : $this->empty_state();
				break;
			case 'fwrite':
			case 'fputs':
				$content = isset( $args[1] ) ? $args[1] : $this->empty_state();
				break;
			case 'copy':
				$content = isset( $args[0] ) ? $args[0] : $this->empty_state();
				$path = isset( $args[1] ) ? $args[1] : $this->empty_state();
				if ( null !== $content['literal'] && preg_match( '~^(?:https?|ftp)://~i', $content['literal'] ) ) {
					$content['remote'] = true;
				}
				break;
			case 'move_uploaded_file':
				$content = isset( $args[0] ) ? $args[0] : $this->empty_state();
				$path = isset( $args[1] ) ? $args[1] : $this->empty_state();
				break;
			case 'rename':
				$path = isset( $args[1] ) ? $args[1] : $this->empty_state();
				break;
		}

		$php_target = ! empty( $path['php_path_hint'] ) || ( null !== $path['literal'] && preg_match( '~\\.(?:php\\d*|phtml|phar)(?:$|[?#])~i', $path['literal'] ) );

		if ( $content['remote'] && $php_target ) {
			$this->add_finding( 'critical', 98, 'dataflow_remote_php_write', 'Remotely sourced payload is written into an executable PHP file', $line, true, $content['sources'] );
			return;
		}

		if ( ( $content['tainted'] || $content['decoded'] ) && $php_target ) {
			$this->add_finding( 'critical', 98, 'dataflow_tainted_php_write', 'Request-controlled or decoded data is written into an executable PHP file', $line, true, $content['sources'] );
			return;
		}

		if ( $path['tainted'] && ( $content['tainted'] || $content['decoded'] || $content['remote'] ) ) {
			$this->add_finding( 'high', 94, 'dataflow_arbitrary_file_write', 'Request-controlled path and untrusted content reach a filesystem write', $line, true );
		}
	}

	private function apply_curl_setopt( array $argument_tokens, array $args ) {
		if ( ! isset( $args[0], $args[2] ) ) {
			return;
		}

		$this->merge_state_into_argument_variable( $argument_tokens, 0, $args[2], 'curl' );
	}

	private function apply_curl_setopt_array( array $argument_tokens, array $args ) {
		if ( ! isset( $args[0], $args[1] ) ) {
			return;
		}

		$this->merge_state_into_argument_variable( $argument_tokens, 0, $args[1], 'curl' );
	}

	private function merge_state_into_argument_variable( array $argument_tokens, $argument_index, array $extra_state, $transport = null ) {
		if ( ! isset( $argument_tokens[ $argument_index ] ) ) {
			return;
		}

		$tokens = $this->trim_tokens( $argument_tokens[ $argument_index ] );
		if ( empty( $tokens ) || T_VARIABLE !== $tokens[0]['id'] ) {
			return;
		}

		$ref = $this->parse_variable_reference( $tokens, 0 );
		if ( null === $ref ) {
			return;
		}

		$state = $this->merge_states( $this->get_variable_state( $ref['key'] ), $extra_state );
		if ( null !== $transport ) {
			$state['transport'] = $transport;
		}
		$this->set_variable_state( $ref['key'], $state );
	}



	private function report_outbound_sink( $transport, array $payload, array $target, $line, $rule ) {
		// A proven WordPress self/local URL is not outbound exfiltration. Keep the
		// suppression deliberately narrow: if the target is request-controlled,
		// remotely sourced, or contains independent remote-URL evidence, the finding
		// remains reportable.
		if (
			'HTTP' === $transport
			&& ! empty( $target['local_url_hint'] )
			&& empty( $target['tainted'] )
			&& empty( $target['remote'] )
			&& empty( $target['remote_url_hint'] )
		) {
			return;
		}

		$summary_param = $this->has_summary_parameter_source( $payload );
		if ( ! $payload['sensitive'] && ! $summary_param ) {
			return;
		}

		$types = array_keys( $payload['sensitive_types'] );
		$high_risk = ! empty( array_intersect( $types, [ 'authorization', 'credential', 'payment', 'session' ] ) );
		$confidence = $high_risk ? 97 : 94;
		$severity = 'high';

		if ( $target['tainted'] && $payload['sensitive'] ) {
			$confidence = 98;
		}

		if ( $summary_param && ! $payload['sensitive'] ) {
			$confidence = 95;
			$severity = 'high';
		}

		$this->add_finding(
			$severity,
			$confidence,
			$rule,
			'Sensitive request/session data is sent through outbound ' . $transport,
			$line,
			true,
			$payload['sources']
		);
	}

	private function has_summary_parameter_source( array $state ) {
		foreach ( array_keys( $state['sources'] ) as $source ) {
			if ( 0 === strpos( $source, 'param:' ) ) {
				return true;
			}
		}

		return false;
	}

	private function evaluate_decoder( $name, array $args, $line ) {
		$input = isset( $args[0] ) ? $args[0] : $this->empty_state();
		$state = $input;
		$state['decoded'] = true;
		$state['transforms'][ $name ] = true;

		if ( null === $input['literal'] || strlen( $input['literal'] ) > self::MAX_STATIC_DECODE_BYTES ) {
			$state['literal'] = null;
			return $state;
		}

		$decoded = $this->safe_decode_literal( $name, $input['literal'] );
		if ( null === $decoded || strlen( $decoded ) > self::MAX_STATIC_DECODE_BYTES ) {
			$state['literal'] = null;
			return $state;
		}

		$state['literal'] = $decoded;
		$this->inspect_decoded_literal( $decoded, $line, count( $state['transforms'] ) );
		return $state;
	}

	private function safe_decode_literal( $name, $value ) {
		switch ( $name ) {
			case 'base64_decode':
				$result = base64_decode( $value, true );
				return false === $result ? null : $result;
			case 'gzinflate':
				$result = @gzinflate( $value, self::MAX_STATIC_DECODE_BYTES );
				return false === $result ? null : $result;
			case 'gzuncompress':
				$result = @gzuncompress( $value, self::MAX_STATIC_DECODE_BYTES );
				return false === $result ? null : $result;
			case 'gzdecode':
				$result = @gzdecode( $value, self::MAX_STATIC_DECODE_BYTES );
				return false === $result ? null : $result;
			case 'str_rot13':
				return str_rot13( $value );
			case 'strrev':
				return strrev( $value );
			case 'rawurldecode':
				return rawurldecode( $value );
			case 'urldecode':
				return urldecode( $value );
			case 'hex2bin':
				if ( 0 !== strlen( $value ) % 2 || ! ctype_xdigit( $value ) ) {
					return null;
				}
				$result = @hex2bin( $value );
				return false === $result ? null : $result;
			case 'convert_uudecode':
				$result = @convert_uudecode( $value );
				return false === $result ? null : $result;
		}

		return null;
	}

	private function inspect_decoded_literal( $decoded, $line, $layers ) {
		if ( '' === $decoded ) {
			return;
		}

		foreach ( $this->known_iocs as $ioc ) {
			if ( false !== stripos( $decoded, $ioc ) ) {
				$this->add_finding( 'critical', 99, 'dataflow_decoded_known_ioc', 'Statically decoded payload contains a known malware/webshell indicator', $line, true );
				break;
			}
		}

		$php_context = false !== stripos( $decoded, '<?php' ) || false !== stripos( $decoded, '<?=' );
		$dangerous_php = preg_match( '~(?:eval\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|base64_decode\s*\(|gzinflate\s*\(|file_put_contents\s*\(|\$_(?:GET|POST|REQUEST|COOKIE))~i', $decoded );

		$child_findings = [];
		if ( $this->analysis_depth < self::MAX_RECURSION_DEPTH && $php_context && strlen( $decoded ) <= self::MAX_STATIC_DECODE_BYTES ) {
			$child = new self( $this->known_iocs );
			$child_findings = $child->analyze( $decoded, $line, $this->analysis_depth + 1 );
			foreach ( $child_findings as $finding ) {
				$finding['rule'] = 'decoded_' . $finding['rule'];
				$this->add_finding( $finding['severity'], $finding['confidence'], $finding['rule'], 'Decoded payload: ' . $finding['description'], $line, true );
			}
		}

		if ( $php_context && $dangerous_php && empty( $child_findings ) ) {
			$this->add_finding(
				'critical',
				$layers >= 2 ? 99 : 97,
				'dataflow_decoded_php_payload',
				'Statically decoded payload contains executable PHP/backdoor primitives',
				$line,
				true
			);
		}

		$dangerous_js = preg_match( '~(?:eval\s*\(|new\s+Function\s*\(|atob\s*\(|document\.write\s*\(|location\.(?:href|replace)\s*=?)~i', $decoded );
		if ( $dangerous_js && ( false !== stripos( $decoded, '<script' ) || strlen( $decoded ) > 200 ) ) {
			$this->add_finding( 'high', 91, 'dataflow_decoded_js_payload', 'Statically decoded payload contains suspicious executable JavaScript', $line, true );
		}

	}

	private function analyze_global_patterns( $source ) {
		$line = 1;
		$matches = [];

		if ( 1 === preg_match( '~bindec\s*\([\s\S]{0,500}str_replace\s*\([\s\S]{0,500}(?:chr\s*\(\s*9\s*\)|["\']\\t["\'])[\s\S]{0,500}(?:chr\s*\(\s*32\s*\)|["\'] ["\'])~i', $source, $matches, PREG_OFFSET_CAPTURE ) ) {
			$line = $this->absolute_line( 1 + substr_count( substr( $source, 0, $matches[0][1] ), "\n" ) );
			$this->add_finding( 'high', 90, 'dataflow_whitespace_steganography', 'Whitespace-to-binary decoding pattern commonly used to conceal PHP payloads', $line, true );
		}

	}

	/**
	 * Build simple interprocedural summaries for named local functions.
	 *
	 * Every parameter is marked with a distinct symbolic taint source and the
	 * function body is analyzed once. Findings retain the parameter sources
	 * that reached a dangerous sink, allowing call sites to be checked later.
	 */
	private function collect_function_summaries( array $tokens ) {
		$summaries = [];

		for ( $i = 0; $i < count( $tokens ); $i++ ) {
			if ( T_FUNCTION !== $tokens[ $i ]['id'] ) {
				continue;
			}

			$name_index = $this->next_significant_index( $tokens, $i + 1 );
			if ( null !== $name_index && '&' === $tokens[ $name_index ]['text'] ) {
				$name_index = $this->next_significant_index( $tokens, $name_index + 1 );
			}
			if ( null === $name_index || T_STRING !== $tokens[ $name_index ]['id'] ) {
				continue; // Closure/anonymous function.
			}

			$name = strtolower( $tokens[ $name_index ]['text'] );
			$open_params = $this->next_significant_index( $tokens, $name_index + 1 );
			if ( null === $open_params || '(' !== $tokens[ $open_params ]['text'] ) {
				continue;
			}
			$close_params = $this->find_matching( $tokens, $open_params, '(', ')' );
			if ( null === $close_params ) {
				continue;
			}

			$params = [];
			foreach ( $this->split_arguments( array_slice( $tokens, $open_params + 1, $close_params - $open_params - 1 ) ) as $param_tokens ) {
				$param_name = null;
				foreach ( $param_tokens as $param_token ) {
					if ( T_VARIABLE === $param_token['id'] ) {
						$param_name = $param_token['text'];
						break;
					}
				}
				$params[] = $param_name;
			}

			$open_body = $this->next_significant_index( $tokens, $close_params + 1 );
			if ( null === $open_body || '{' !== $tokens[ $open_body ]['text'] ) {
				continue;
			}
			$close_body = $this->find_matching( $tokens, $open_body, '{', '}' );
			if ( null === $close_body ) {
				continue;
			}

			$child = new self( $this->known_iocs );
			$child->base_line = 1;
			$child->analysis_depth = $this->analysis_depth;
			$child->scopes = [ $child->new_scope() ];
			$child->function_summaries = [];
			foreach ( $params as $param_index => $param_name ) {
				if ( null !== $param_name ) {
					$child->set_variable_state( $param_name, $child->tainted_state( 'param:' . $param_index ) );
				}
			}

			$body_tokens = array_slice( $tokens, $open_body + 1, $close_body - $open_body - 1 );
			$body_source = $this->tokens_to_source( $body_tokens );
			if ( $this->looks_like_local_decoder_function( $body_source ) ) {
				$this->local_decoder_functions[ $name ] = true;
			}
			$child->analyze_tokens( $body_tokens );

			foreach ( $child->findings as $finding ) {
				$param_indexes = [];
				foreach ( isset( $finding['sources'] ) ? $finding['sources'] : [] as $source ) {
					if ( 0 === strpos( $source, 'param:' ) ) {
						$param_indexes[] = (int) substr( $source, 6 );
					}
				}

				if ( empty( $param_indexes ) ) {
					continue;
				}

				$key = $finding['rule'] . ':' . implode( ',', array_unique( $param_indexes ) );
				$summaries[ $name ][ $key ] = [
					'severity'      => $finding['severity'],
					'confidence'    => $finding['confidence'],
					'rule'          => $finding['rule'],
					'param_indexes' => array_values( array_unique( $param_indexes ) ),
				];
			}

			$i = $close_body;
		}

		foreach ( $summaries as $name => $items ) {
			$summaries[ $name ] = array_values( $items );
		}

		return $summaries;
	}

	/**
	 * Identify local helpers whose return value is likely a decoded/deobfuscated
	 * string. This does not create a finding by itself; it only tags the return
	 * value so a later dangerous sink can be evaluated with more context.
	 */
	private function looks_like_local_decoder_function( $source ) {
		if ( false === stripos( $source, 'return' ) ) {
			return false;
		}

		foreach ( self::DECODERS as $decoder ) {
			if ( false !== stripos( $source, $decoder . '(' ) ) {
				return true;
			}
		}

		return false !== stripos( $source, 'hex2bin(' )
			&& false !== stripos( $source, 'ord(' )
			&& false !== stripos( $source, 'chr(' )
			&& false !== strpos( $source, '^' );
	}

	private function tokens_to_source( array $tokens ) {
		$source = '';
		foreach ( $tokens as $token ) {
			$source .= $token['text'];
		}
		return $source;
	}

	/**
	 * Apply a local function summary at a concrete call site.
	 */
	private function apply_local_function_summary( $name, array $args, $line ) {
		if ( ! isset( $this->function_summaries[ $name ] ) ) {
			return;
		}

		foreach ( $this->function_summaries[ $name ] as $summary ) {
			$family = $this->sink_family_from_rule( $summary['rule'] );
			$triggered = false;
			$sources = [];
			foreach ( $summary['param_indexes'] as $param_index ) {
				if ( ! isset( $args[ $param_index ] ) ) {
					continue;
				}
				$arg = $args[ $param_index ];
				$matches = 'exfiltration' === $family
					? $arg['sensitive']
					: ( $arg['tainted'] || $arg['decoded'] || $arg['remote'] );
				if ( $matches ) {
					$triggered = true;
					$sources += $arg['sources'];
				}
			}

			if ( ! $triggered ) {
				continue;
			}

			$rule = 'dataflow_local_function_' . preg_replace( '~[^a-z0-9_]+~', '_', $name ) . '_' . $family;
			$description = 'Untrusted argument reaches ' . $this->sink_family_label( $family ) . ' through local function ' . $name . '()';
			if ( 'exfiltration' === $family ) {
				$description = 'Sensitive request/session argument reaches an outbound transfer through local function ' . $name . '()';
			}
			$this->add_finding(
				$summary['severity'],
				min( 98, max( 90, (int) $summary['confidence'] ) ),
				$rule,
				$description,
				$line,
				true,
				$sources
			);
		}
	}

	private function sink_family_from_rule( $rule ) {
		if ( false !== strpos( $rule, 'exfil' ) ) {
			return 'exfiltration';
		}
		if ( false !== strpos( $rule, 'command' ) || false !== strpos( $rule, 'backtick' ) ) {
			return 'command';
		}
		if ( false !== strpos( $rule, 'include' ) ) {
			return 'include';
		}
		if ( false !== strpos( $rule, 'write' ) ) {
			return 'file_write';
		}
		if ( false !== strpos( $rule, 'callback' ) ) {
			return 'callback';
		}
		return 'code_execution';
	}

	private function sink_family_label( $family ) {
		switch ( $family ) {
			case 'exfiltration':
				return 'outbound transfer of sensitive request/session data';
			case 'command':
				return 'OS command execution';
			case 'include':
				return 'include/require';
			case 'file_write':
				return 'an executable/untrusted filesystem write';
			case 'callback':
				return 'a dangerous dynamic callback';
			default:
				return 'dynamic PHP code execution';
		}
	}

	private function set_variable_state( $key, array $state ) {
		$scope_index = count( $this->scopes ) - 1;
		$this->scopes[ $scope_index ]['vars'][ $key ] = $state;
	}

	private function get_variable_state( $key ) {
		$root = preg_replace( '~\[.*$~', '', $key );
		if ( in_array( $root, self::SUPERGLOBALS, true ) ) {
			return $this->tainted_state( $key );
		}

		for ( $i = count( $this->scopes ) - 1; $i >= 0; $i-- ) {
			if ( isset( $this->scopes[ $i ]['vars'][ $key ] ) ) {
				return $this->scopes[ $i ]['vars'][ $key ];
			}

			if ( false !== strpos( $key, '[' ) && isset( $this->scopes[ $i ]['vars'][ $root ] ) ) {
				$parent = $this->scopes[ $i ]['vars'][ $root ];
				if ( $parent['tainted'] ) {
					return $this->refine_sensitive_state_for_reference( $parent, $key );
				}
			}

			if ( $this->scopes[ $i ]['symbol_table_tainted'] ) {
				return $this->tainted_state( 'dynamic-symbol-table' );
			}
		}

		return $this->empty_state();
	}

	private function mark_symbol_table_tainted() {
		$scope_index = count( $this->scopes ) - 1;
		$this->scopes[ $scope_index ]['symbol_table_tainted'] = true;
	}

	private function empty_state() {
		return [
			'tainted'      => false,
			'sensitive'    => false,
			'literal'      => null,
			'decoded'      => false,
			'remote'       => false,
			'remote_url_hint' => false,
			'local_url_hint'  => false,
			'php_path_hint'=> false,
			'transport'    => null,
			'sources'      => [],
			'sensitive_types' => [],
			'transforms'   => [],
		];
	}

	private function literal_state( $literal ) {
		$state = $this->empty_state();
		$state['literal'] = (string) $literal;
		$state['remote_url_hint'] = (bool) preg_match( '~(?:https?|ftp)://~i', $state['literal'] );
		$state['php_path_hint'] = (bool) preg_match( '~\.(?:php\d*|phtml|phar)(?:$|[?#])~i', $state['literal'] );
		return $state;
	}

	private function tainted_state( $source ) {
		$state = $this->empty_state();
		$state['tainted'] = true;
		$state['sources'][ $source ] = true;
		foreach ( $this->sensitive_types_for_source( $source ) as $type ) {
			$state['sensitive'] = true;
			$state['sensitive_types'][ $type ] = true;
		}
		return $state;
	}

	private function merge_states( array $left, array $right ) {
		$state = $this->empty_state();
		$state['tainted'] = $left['tainted'] || $right['tainted'];
		$state['sensitive'] = $left['sensitive'] || $right['sensitive'];
		$state['decoded'] = $left['decoded'] || $right['decoded'];
		$state['remote'] = $left['remote'] || $right['remote'];
		$state['remote_url_hint'] = $left['remote_url_hint'] || $right['remote_url_hint'];
		$state['local_url_hint'] = $left['local_url_hint'] || $right['local_url_hint'];
		$state['php_path_hint'] = $left['php_path_hint'] || $right['php_path_hint'];
		$state['transport'] = null !== $left['transport'] ? $left['transport'] : $right['transport'];
		$state['sources'] = $left['sources'] + $right['sources'];
		$state['sensitive_types'] = $left['sensitive_types'] + $right['sensitive_types'];
		$state['transforms'] = $left['transforms'] + $right['transforms'];
		return $state;
	}

	private function sensitive_types_for_source( $source ) {
		$source = strtolower( (string) $source );
		$types = [];

		if ( false !== strpos( $source, '$_cookie' ) || false !== strpos( $source, 'http_cookie' ) ) {
			$types['session'] = true;
		}

		if ( false !== strpos( $source, 'authorization' ) || false !== strpos( $source, 'php_auth_pw' ) || false !== strpos( $source, 'php_auth_user' ) ) {
			$types['authorization'] = true;
		}

		if ( preg_match( '~(?:^|[^a-z0-9])(?:password|passwd|passphrase|pwd|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer|jwt|private[_-]?key|secret)(?:$|[^a-z0-9])~i', $source ) ) {
			$types['credential'] = true;
		}

		if ( preg_match( '~(?:^|[^a-z0-9])(?:card[_-]?(?:number|no)|credit[_-]?card|cc[_-]?(?:number|no)|pan|cvv|cvc|card[_-]?security|expiry|expiration)(?:$|[^a-z0-9])~i', $source ) ) {
			$types['payment'] = true;
		}

		return array_keys( $types );
	}

	private function refine_sensitive_state_for_reference( array $state, $reference ) {
		foreach ( $this->sensitive_types_for_source( $reference ) as $type ) {
			$state['sensitive'] = true;
			$state['sensitive_types'][ $type ] = true;
		}

		return $state;
	}

	private function merge_argument_states( array $states ) {
		$merged = $this->empty_state();
		foreach ( $states as $state ) {
			$merged = $this->merge_states( $merged, $state );
		}
		return $merged;
	}

	private function merge_concatenation_states( array $states ) {
		$state = $this->merge_argument_states( $states );
		$literal = '';
		foreach ( $states as $part ) {
			if ( null === $part['literal'] ) {
				$literal = null;
				break;
			}
			$literal .= $part['literal'];
		}
		$state['literal'] = $literal;
		return $state;
	}

	private function any_state( array $states, $key ) {
		foreach ( $states as $state ) {
			if ( ! empty( $state[ $key ] ) ) {
				return true;
			}
		}

		return false;
	}

	private function split_arguments( array $tokens ) {
		return $this->split_top_level( $tokens, ',' );
	}

	private function split_top_level( array $tokens, $separator ) {
		$parts = [];
		$current = [];
		$round = 0;
		$square = 0;
		$curly = 0;

		foreach ( $tokens as $token ) {
			$text = $token['text'];
			if ( '(' === $text ) {
				$round++;
			} elseif ( ')' === $text ) {
				$round--;
			} elseif ( '[' === $text ) {
				$square++;
			} elseif ( ']' === $text ) {
				$square--;
			} elseif ( '{' === $text ) {
				$curly++;
			} elseif ( '}' === $text ) {
				$curly--;
			}

			if ( $separator === $text && 0 === $round && 0 === $square && 0 === $curly ) {
				$parts[] = $current;
				$current = [];
				continue;
			}
			$current[] = $token;
		}

		$parts[] = $current;
		return $parts;
	}

	private function find_statement_end( array $tokens, $start ) {
		$round = 0;
		$square = 0;
		$curly = 0;
		$count = count( $tokens );
		for ( $i = $start; $i < $count; $i++ ) {
			$text = $tokens[ $i ]['text'];
			if ( '(' === $text ) {
				$round++;
			} elseif ( ')' === $text ) {
				$round = max( 0, $round - 1 );
			} elseif ( '[' === $text ) {
				$square++;
			} elseif ( ']' === $text ) {
				$square = max( 0, $square - 1 );
			} elseif ( '{' === $text ) {
				$curly++;
			} elseif ( '}' === $text ) {
				if ( 0 === $curly && 0 === $round && 0 === $square ) {
					return $i;
				}
				$curly = max( 0, $curly - 1 );
			} elseif ( ';' === $text && 0 === $round && 0 === $square && 0 === $curly ) {
				return $i;
			}
		}
		return $count - 1;
	}

	private function find_matching( array $tokens, $open_index, $open, $close ) {
		$depth = 0;
		for ( $i = $open_index; $i < count( $tokens ); $i++ ) {
			if ( $open === $tokens[ $i ]['text'] ) {
				$depth++;
			} elseif ( $close === $tokens[ $i ]['text'] ) {
				$depth--;
				if ( 0 === $depth ) {
					return $i;
				}
			}
		}
		return null;
	}

	private function find_text_token( array $tokens, $text, $start ) {
		for ( $i = $start; $i < count( $tokens ); $i++ ) {
			if ( $text === $tokens[ $i ]['text'] ) {
				return $i;
			}
		}

		return null;
	}

	private function is_wrapped_in_parentheses( array $tokens ) {
		if ( count( $tokens ) < 2 || '(' !== $tokens[0]['text'] || ')' !== $tokens[ count( $tokens ) - 1 ]['text'] ) {
			return false;
		}
		$close = $this->find_matching( $tokens, 0, '(', ')' );
		return $close === count( $tokens ) - 1;
	}

	private function trim_tokens( array $tokens ) {
		while ( ! empty( $tokens ) && $this->is_trivia( $tokens[0] ) ) {
			array_shift( $tokens );
		}
		while ( ! empty( $tokens ) && $this->is_trivia( $tokens[ count( $tokens ) - 1 ] ) ) {
			array_pop( $tokens );
		}
		while ( ! empty( $tokens ) && '@' === $tokens[0]['text'] ) {
			array_shift( $tokens );
			while ( ! empty( $tokens ) && $this->is_trivia( $tokens[0] ) ) {
				array_shift( $tokens );
			}
		}
		return $tokens;
	}

	private function is_trivia( array $token ) {
		return in_array( $token['id'], [ T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ], true );
	}

	private function next_significant_index( array $tokens, $start ) {
		for ( $i = $start; $i < count( $tokens ); $i++ ) {
			if ( ! $this->is_trivia( $tokens[ $i ] ) ) {
				return $i;
			}
		}

		return null;
	}

	private function previous_significant_index( array $tokens, $start ) {
		for ( $i = $start; $i >= 0; $i-- ) {
			if ( ! $this->is_trivia( $tokens[ $i ] ) ) {
				return $i;
			}
		}

		return null;
	}

	private function decode_php_string_literal( $literal ) {
		if ( strlen( $literal ) < 2 ) {
			return $literal;
		}
		$quote = $literal[0];
		$value = substr( $literal, 1, -1 );
		if ( "'" === $quote ) {
			return str_replace( [ "\\\\", "\\'" ], [ "\\", "'" ], $value );
		}
		return stripcslashes( $value );
	}

	private function absolute_line( $token_line ) {
		return $this->base_line + max( 1, (int) $token_line ) - 1;
	}

	private function add_finding( $severity, $confidence, $rule, $description, $line, $line_is_absolute = false, array $sources = [] ) {
		$key = $rule;
		if ( isset( $this->seen[ $key ] ) ) {
			return;
		}
		$this->seen[ $key ] = true;
		$this->findings[] = [
			'severity'    => $severity,
			'confidence'  => (int) $confidence,
			'rule'        => $rule,
			'description' => $description,
			'line'        => $line_is_absolute ? max( 1, (int) $line ) : $this->absolute_line( $line ),
			'sources'     => array_keys( $sources ),
		];
	}
}
