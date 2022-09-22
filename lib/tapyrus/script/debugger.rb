module Tapyrus
  class ScriptDebugger
    attr_reader :script_pubkey
    attr_reader :script_sig
    attr_reader :tx_checker
    attr_reader :interpreter

    attr_accessor :target_script
    attr_accessor :is_redeem
    attr_accessor :chunk_index
    attr_accessor :chunk_size
    attr_accessor :chunks
    attr_accessor :stack_copy

    # @param [Tapyrus::Script] script_pubkey
    # @param [Tapyrus::Script] script_sig
    # @param [Tapyrus::Tx] tx (optional)
    # @param [Integer] index (optional) input index
    # @raise [ArgumentError]
    def initialize(script_pubkey:, script_sig:, tx: nil, index: nil)
      @script_pubkey = script_pubkey
      @script_sig = script_sig
      if tx
        raise ArgumentError, 'index should be specified' if index.nil?
        @tx_checker = Tapyrus::TxChecker.new(tx: tx, input_index: index)
        if (tx_checker.tx.in.size - 1) < tx_checker.input_index
          raise ArgumentError, "Tx does not have #{tx_checker.input_index}-th input."
        end
      else
        @tx_checker = EmptyTxChecker.new
      end
      @interpreter = Tapyrus::ScriptInterpreter.new(checker: tx_checker)
      @interpreter.reset_params
      @chunk_index = 0
      @target_script = script_sig
      @chunks = target_script.chunks.each
      @chunk_size = target_script.chunks.length
      @stack_copy = nil
    end

    def step
      if chunk_size == chunk_index
        if target_script == script_sig
          @stack_copy = interpreter.stack.dup
          @target_script = script_pubkey
          @interpreter.reset_params
          @chunks = target_script.chunks.each
          @chunk_index = 0
          @chunk_size = target_script.chunks.length
        elsif target_script == script_pubkey
          if interpreter.stack.empty? || !interpreter.cast_to_bool(interpreter.stack.last.htb)
            return(
              StepResult.error(
                current_stack: interpreter.stack.dup,
                error: 'Script evaluated without error but finished with a false/empty top stack element'
              )
            )
          end
          if script_pubkey.p2sh?
            interpreter.stack = stack_copy
            redeem_script = Tapyrus::Script.parse_from_payload(interpreter.stack.pop.htb)
            @target_script = redeem_script
            @chunks = target_script.chunks.each
            @chunk_index = 0
            @chunk_size = target_script.chunks.length
          else
            return StepResult.finished(current_stack: interpreter.stack.dup)
          end
        else
          return StepResult.finished(current_stack: interpreter.stack.dup)
        end
      end
      result = step_process(interpreter, target_script, chunks.next, chunk_index, is_redeem)
      return result if result.is_a?(StepResult)
      @chunk_index += 1
      StepResult.success(current_stack: interpreter.stack.dup, message: result)
    end

    private

    def step_process(interpreter, script, chunk, index, is_redeem_script)
      message =
        chunk.pushdata? ? "PUSH #{chunk.pushed_data.bth}" : "APPLY #{Tapyrus::Opcodes.opcode_to_name(chunk.opcode)}"
      begin
        result = interpreter.next_step(script, chunk, index, is_redeem_script)
        if result.is_a?(FalseClass)
          return(
            StepResult.error(current_stack: interpreter.stack.dup, error: "script failed. Reason: #{interpreter.error}")
          )
        end
        message
      rescue TxUnspecifiedError => e
        return StepResult.error(current_stack: interpreter.stack.dup, error: e.message, message: message)
      end
    end
  end

  class StepResult
    STATUS_RUNNING = 'running'
    STATUS_HALT = 'halt'
    STATUS_FINISHED = 'finished'

    STATUSES = [STATUS_RUNNING, STATUS_HALT, STATUS_FINISHED]

    attr_reader :status
    attr_reader :current_stack
    attr_reader :message
    attr_reader :error

    # @param [String] status
    # @param [Array] current_stack
    # @param [String] message
    # @param [String] error an error message.
    def initialize(status, current_stack: [], message: nil, error: nil)
      raise ArgumentError, 'Unsupported status specified.' unless STATUSES.include?(status)
      @status = status
      @current_stack = current_stack
      @error = error
      @message = message
    end

    def self.error(current_stack: [], error:, message: nil)
      StepResult.new(STATUS_HALT, current_stack: current_stack, error: error, message: message)
    end

    def self.success(current_stack: [], message: nil)
      StepResult.new(STATUS_RUNNING, current_stack: current_stack, message: message)
    end

    def self.finished(current_stack: [])
      StepResult.new(STATUS_FINISHED, current_stack: current_stack)
    end

    def halt?
      status == STATUS_HALT
    end

    def finished?
      status == STATUS_FINISHED
    end

    def stack_table
      rows = current_stack.map { |s| [s] }.reverse
      Terminal::Table.new(title: 'Current Stack', rows: rows)
    end

    def print_result
      puts message if message
      puts stack_table
    end
  end

  class TxUnspecifiedError < StandardError
  end

  class EmptyTxChecker
    def check_sig(script_sig, pubkey, script_code)
      raise TxUnspecifiedError, 'Signature verification failed. You need to enter tx and input index.'
    end
    def verify_sig(sig, pubkey, digest, allow_hybrid: false)
      raise TxUnspecifiedError, 'Signature verification failed. You need to enter tx and input index.'
    end
  end
end
