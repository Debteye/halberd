module Halberd
  class Utils
    def tag_xml(xml, ele_name, input)
      case input
      when Array
        input.each do |cred|
          case cred
          when Hash
            tag_hash(xml, ele_name, cred)
          when nil
            xml.tag!(ele_name.to_s.lower_camelcase, nil, 'xsi:nil' => true)
          else
            xml.tag!(ele_name.to_s.lower_camelcase, cred) unless ele_name =~ /@/
          end
        end
      end
      xml
    end

    def tag_hash(xml, ele_name, cred)
      xsi_type = cred[:'@xsi:type']
      if xsi_type
        xsi_type = xsi_type.gsub("ns1", "common")
        xml.tag!(ele_name.to_s.lower_camelcase, 'xsi:type' => xsi_type) do
          cred.each do |name, value|
            case value
            when Array
              tag_xml(xml, name, value)
            when Hash
              tag_hash(xml, name, value)
            when nil
              xml.tag!(name.to_s.lower_camelcase, nil, 'xsi:nil' => true)
            else
              xml.tag!(name.to_s.lower_camelcase, value) unless name =~ /@/
            end
          end
        end
      else
        xml.tag!(ele_name.to_s.lower_camelcase) do
          cred.each do |name, value|
            case value
            when Array
              tag_xml(xml, name, value)
            when Hash
              tag_hash(xml, name, value)
            when nil
              xml.tag!(name.to_s.lower_camelcase, nil, 'xsi:nil' => true)
            else
              xml.tag!(name.to_s.lower_camelcase, value) unless name =~ /@/
            end
          end
        end
      end
      xml
    end
  end
end
